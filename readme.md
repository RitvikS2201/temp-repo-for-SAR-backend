# Security Rules
Security Rules are used to secure the database with user authentication and data validation.<br>

Data being written to the database is accessed with `request.data`, info on the user writing to the database is accessed with `request.auth`, and data already in the database is accessed with `resource.data`.<br>

Data types can be tested using the `is` condition. The supported data types are:
- `bool`
- `int`
- `float`
- `number`
- `string`
- `list`
- `map`
- `timestamp`
- `duration`
- `path`
- `latlong`


Keys of a map can be accessed as a list of strings using `data.keys()`.<br>
The length of a map, list, or string can be determined using `data.size()`.<br>

In `match` statements, the values in braces in the path are available as variables. If the variable name is followed by `=**`, it will match the remainder of the path, including subcollections.
```
match /collection/{documentId} {
    allow write: if documentId is string
}

match /collection/{document=**} {
    // Matches on /collection/documentId, /collection/documentId/subcollection/anotherId, etc.
}
```

External documents in the database can be accessed with `get(path)`, which fetches the document at the provided path, or `exists(path)`, which returns a boolean representing if a document exists at the provided path.<br>

The `request.method` variable is a string representing the CRUD operation: 'create', 'update', or 'delete'. Passing this argument allows for tests to be performed based on the operation the user is trying to commit. For example, the following condition can be used in to minimze fetches to other documents in the database.
```
(request.method == 'update' && request.data.field == resource.data.field) || request.data.field == get(/databases/$(database)/documents/incidents/$(incidentId)/collection/$(documentId)).data.field
```
This allows for the `get()` function, which is an external fetch, will only get called when a new document is created or, in the case of updating an existing document, the value of the field being written is different than what is already in the database.

## Writing Security Rules
Start with the following template:
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    function validPeriod(period) {
      return period is map &&
             period.keys() == ['begin', 'end'] &&
             period.begin is timestamp &&
             period.end is timestamp &&
             period.end > period.begin;
    }
	  
    function validUser(auth, user) {
      return user is map &&
	         user.keys.hasOnly(['uid', 'name', 'phone', 'email') &&
	         user.uid == auth.uid &&
	         user.name == auth.displayName &&
	         (user.phone == null || user.phone == auth.token.phone) &&
	         (user.email == null || user.email == auth.token.email)
    }
    
    function validComments(comments, required) {
      return (required != true && comments == null) ||
             (comments is string && comments.size() <= 2048);
    }
  
    match /incidents/{incidentId} {
      match /<collection>/{documentId} {
        function auth<Document>R() {
          return false;
        }

        function auth<Document>W() {
          return false;
        }

        function valid<Document>() {          
          let preparedBy = validUser(request.auth, request.data.preparedBy)
        
          let comments = validComments(request.data.comments, false);

          return field1 && preparedBy && comments;
        }
        
        allow read: if auth<Document>R();

        allow create: if request.data.keys().hasOnly(['field1', 'field2', 'preparedBy', 'comments']) && 
                         valid<Document>() && 
                         auth<Document>W();

        allow update: if request.data.keys().hasOnly(['field1', 'field2', 'preparedBy', 'comments']) && 
                         valid<Document>() && 
                         authDocumentW();

        allow delete: if auth<Document>W();
      }
    }
  }
}
```
*Subject used as example document*<br>
Replace <<x>collection> in `match /<collection>/{documentId}` with your collection name. (should be plural of document name)
```
match /subjects/{documentId}
```

Replace <<x>Document> in `auth<Document>R()`, `auth<Document>W()`, and `valid<Document>()` with document name. (should be singular of collection name)
```
function authSubjectR() {}
function authSubjectW() {}
function validSubject() {}
```

In `valid<Document>W()`, test each field and store the condition in a variable. Then, after each field has been tested, return each variable ANDed together.<br>
If a JSON schema exists for the document, the conditions must match the data types of each field according to the schema.<br>
Optional fields must include a null condition, which will evaluate to `true` when the field is not present.
```
function validSubject() {
  let name = request.data.name is string
  let age = request.data.age == null || (request.data.age is int && request.data.age >= 0) // optional
  ...

  return name && age && ...
}
```

Under `allow create` and `allow update`, test for the keys in the data being submitted before calling `valid<Document>()` calling `request.data.keys().hasOnly([])`. The array passed to `hasOnly([])` is a list of all required and optional keys for the document. This allows for short circuit evaluation ensuring the data being written contains the proper fields before any potentially stateful checks need to be made. 
```
allow create: if request.data.keys().hasOnly(['name', 'age']) && validSubject() && authSubjectW()
```

## References:
- Security Rules Documentation: https://firebase.google.com/docs/firestore/security/get-started
- Security Rules Reference: https://firebase.google.com/docs/reference/rules/rules
- Spreadsheet: https://docs.google.com/spreadsheets/d/1QeV4n392TnDTB93Pe_ivqnqwa8HcyYy3ajKTlTwpuXw/edit?usp=sharing
- Links to Form PDFs: https://docs.google.com/spreadsheets/d/1Oxw1bDAessLtFLoK7pCsy006UQPElArbrhktFdJSsJM/edit#gid=0
- Backend Notes: https://docs.google.com/document/d/13cE5knNhkNTNNTGuIiga14dxnRTeUcjIh1pjZ9WhmUs/edit
- Trello Board: https://trello.com/b/VN494iz9/back-end-development
- Search Management Training Archive: https://drive.google.com/drive/folders/1ppzwD6izB4Mya1mmUHES6XZU3l_EP1c9
