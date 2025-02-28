# ToolDescription
## Default
### Description
  FaultHunter is the coding rule violation checker module of SourceMeter. This module makes it possible to identify common RPG coding rule violations in the code (so-called bad practices). The algorithms implemented in the FaultHunter module work on the precise Abstract Semantic Graph of SourceMeter which results in higher precision and recall compared to other tools with a rougher syntactic analyzer.

### ID=FaultHunter

# TagMetadata
## collection
### CWE
##### Url=https://cwe.mitre.org
##### Description
  Common Weakness Enumeration (CWE™)

#### 113
##### Url=https://cwe.mitre.org/data/definitions/113.html
##### Description
  Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')

#### 116
##### Url=https://cwe.mitre.org/data/definitions/116.html
##### Description
  Improper Encoding or Escaping of Output

#### 171
##### Url=https://cwe.mitre.org/data/definitions/171.html
##### Description
  Cleansing, Canonicalization, and Comparison Errors

#### 20
##### Url=https://cwe.mitre.org/data/definitions/20.html
##### Description
  Improper Input Validation

#### 22
##### Url=https://cwe.mitre.org/data/definitions/22.html
##### Description
  Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

#### 23
##### Url=https://cwe.mitre.org/data/definitions/23.html
##### Description
  Relative Path Traversal

#### 256
##### Url=https://cwe.mitre.org/data/definitions/256.html
##### Description
  Plaintext Storage of a Password

#### 258
##### Url=https://cwe.mitre.org/data/definitions/258.html
##### Description
  Empty Password in Configuration File

#### 259
##### Url=https://cwe.mitre.org/data/definitions/259.html
##### Description
  Use of Hard-coded Password

#### 261
##### Url=https://cwe.mitre.org/data/definitions/261.html
##### Description
  Weak Encoding for Password

#### 266
##### Url=https://cwe.mitre.org/data/definitions/266.html
##### Description
  Incorrect Privilege Assignment

#### 310
##### Url=https://cwe.mitre.org/data/definitions/310.html
##### Description
  Cryptographic Issues

#### 326
##### Url=https://cwe.mitre.org/data/definitions/326.html
##### Description
  Inadequate Encryption Strength

#### 327
##### Url=https://cwe.mitre.org/data/definitions/327.html
##### Description
  Use of a Broken or Risky Cryptographic Algorithm

#### 328
##### Url=https://cwe.mitre.org/data/definitions/328.html
##### Description
  Use of Weak Hash

#### 330
##### Url=https://cwe.mitre.org/data/definitions/330.html
##### Description
  Use of Insufficiently Random Values

#### 331
##### Url=https://cwe.mitre.org/data/definitions/331.html
##### Description
  Insufficient Entropy

#### 332
##### Url=https://cwe.mitre.org/data/definitions/332.html
##### Description
  Insufficient Entropy in PRNG

#### 337
##### Url=https://cwe.mitre.org/data/definitions/337.html
##### Description
  Predictable Seed in Pseudo-Random Number Generator (PRNG)

#### 338
##### Url=https://cwe.mitre.org/data/definitions/338.html
##### Description
  Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

#### 36
##### Url=https://cwe.mitre.org/data/definitions/36.html
##### Description
  Absolute Path Traversal

#### 374
##### Url=https://cwe.mitre.org/data/definitions/374.html
##### Description
  Passing Mutable Objects to an Untrusted Method

#### 375
##### Url=https://cwe.mitre.org/data/definitions/375.html
##### Description
  Returning a Mutable Object to an Untrusted Caller

#### 38
##### Url=https://cwe.mitre.org/data/definitions/38.html
##### Description
  Path Traversal: '\absolute\pathname\here'

#### 395
##### Url=https://cwe.mitre.org/data/definitions/395.html
##### Description
  Use of NullPointerException Catch to Detect NULL Pointer Dereference

#### 397
##### Url=https://cwe.mitre.org/data/definitions/397.html
##### Description
  Declaration of Throws for Generic Exception

#### 443
##### Url=https://cwe.mitre.org/data/definitions/443.html
##### Description
  HTTP response splitting

#### 454
##### Url=https://cwe.mitre.org/data/definitions/454.html
##### Description
  External Initialization of Trusted Variables or Data Stores

#### 470
##### Url=https://cwe.mitre.org/data/definitions/470.html
##### Description
  Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

#### 478
##### Url=https://cwe.mitre.org/data/definitions/478.html
##### Description
  Missing Default Case in Switch Statement

#### 493
##### Url=https://cwe.mitre.org/data/definitions/493.html
##### Description
  Critical Public Variable Without Final Modifier

#### 496
##### Url=https://cwe.mitre.org/data/definitions/496.html
##### Description
  Public Data Assigned to Private Array-Typed Field

#### 500
##### Url=https://cwe.mitre.org/data/definitions/500.html
##### Description
  Public Static Field Not Marked Final

#### 501
##### Url=https://cwe.mitre.org/data/definitions/501.html
##### Description
  Trust Boundary Violation

#### 522
##### Url=https://cwe.mitre.org/data/definitions/522.html
##### Description
  Insufficiently Protected Credentials

#### 539
##### Url=https://cwe.mitre.org/data/definitions/539.html
##### Description
  Use of Persistent Cookies Containing Sensitive Information

#### 545
##### Url=https://cwe.mitre.org/data/definitions/545.html
##### Description
  Use of Dynamic Class Loading

#### 547
##### Url=https://cwe.mitre.org/data/definitions/547.html
##### Description
  Use of Hard-coded, Security-relevant Constants

#### 563
##### Url=https://cwe.mitre.org/data/definitions/563.html
##### Description
  Assignment to Variable without Use

#### 564
##### Url=https://cwe.mitre.org/data/definitions/564.html
##### Description
  SQL Injection: Hibernate

#### 565
##### Url=https://cwe.mitre.org/data/definitions/565.html
##### Description
  Reliance on Cookies without Validation and Integrity Checking

#### 582
##### Url=https://cwe.mitre.org/data/definitions/582.html
##### Description
  Array Declared Public, Final, and Static

#### 584
##### Url=https://cwe.mitre.org/data/definitions/584.html
##### Description
  Return Inside Finally Block

#### 595
##### Url=https://cwe.mitre.org/data/definitions/595.html
##### Description
  Comparison of Object References Instead of Object Contents

#### 597
##### Url=https://cwe.mitre.org/data/definitions/597.html
##### Description
  Use of Wrong Operator in String Comparison

#### 607
##### Url=https://cwe.mitre.org/data/definitions/607.html
##### Description
  Public Static Final Field References Mutable Object

#### 614
##### Url=https://cwe.mitre.org/data/definitions/614.html
##### Description
  Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

#### 643
##### Url=https://cwe.mitre.org/data/definitions/643.html
##### Description
  Improper Neutralization of Data within XPath Expressions ('XPath Injection')

#### 647
##### Url=https://cwe.mitre.org/data/definitions/647.html
##### Description
  Use of Non-Canonical URL Paths for Authorization Decisions

#### 690
##### Url=https://cwe.mitre.org/data/definitions/690.html
##### Description
  Unchecked Return Value to NULL Pointer Dereference

#### 7
##### Url=https://cwe.mitre.org/data/definitions/7.html
##### Description
  J2EE Misconfiguration: Missing Custom Error Page

#### 74
##### Url=https://cwe.mitre.org/data/definitions/74.html
##### Description
  Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')

#### 754
##### Url=https://cwe.mitre.org/data/definitions/754.html
##### Description
  Improper Check for Unusual or Exceptional Conditions

#### 757
##### Url=https://cwe.mitre.org/data/definitions/757.html
##### Description
  Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')

#### 759
##### Url=https://cwe.mitre.org/data/definitions/759.html
##### Description
  Use of a One-Way Hash without a Salt

#### 760
##### Url=https://cwe.mitre.org/data/definitions/760.html
##### Description
  Use of a One-Way Hash with a Predictable Salt

#### 766
##### Url=https://cwe.mitre.org/data/definitions/766.html
##### Description
  Critical Data Element Declared Public

#### 77
##### Url=https://cwe.mitre.org/data/definitions/77.html
##### Description
  Improper Neutralization of Special Elements used in a Command ('Command Injection')

#### 78
##### Url=https://cwe.mitre.org/data/definitions/78.html
##### Description
  Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

#### 784
##### Url=https://cwe.mitre.org/data/definitions/784.html
##### Description
  Reliance on Cookies without Validation and Integrity Checking in a Security Decision

#### 79
##### Url=https://cwe.mitre.org/data/definitions/79.html
##### Description
  Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

#### 798
##### Url=https://cwe.mitre.org/data/definitions/798.html
##### Description
  Use of Hard-coded Credentials

#### 80
##### Url=https://cwe.mitre.org/data/definitions/80.html
##### Description
  Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

#### 820
##### Url=https://cwe.mitre.org/data/definitions/820.html
##### Description
  Missing Synchronization

#### 87
##### Url=https://cwe.mitre.org/data/definitions/87.html
##### Description
  Improper Neutralization of Alternate XSS Syntax

#### 886
##### Url=https://cwe.mitre.org/data/definitions/886.html
##### Description
  Unused entities

#### 89
##### Url=https://cwe.mitre.org/data/definitions/89.html
##### Description
  Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

#### 90
##### Url=https://cwe.mitre.org/data/definitions/90.html
##### Description
  Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

#### 91
##### Url=https://cwe.mitre.org/data/definitions/91.html
##### Description
  XML Injection (aka Blind XPath Injection)

#### 928
##### Url=https://cwe.mitre.org/data/definitions/928.html
##### Description
  Weaknesses in OWASP Top Ten (2013)

#### 93
##### Url=https://cwe.mitre.org/data/definitions/93.html
##### Description
  Improper Neutralization of CRLF Sequences ('CRLF Injection')

#### 943
##### Url=https://cwe.mitre.org/data/definitions/943.html
##### Description
  Improper Neutralization of Special Elements in Data Query Logic

#### 961
##### Url=https://cwe.mitre.org/data/definitions/961.html
##### Description
  Incorrect Exception Behavior

### OWASP
##### Url=https://owasp.org/www-project-top-ten/
##### Description
  Open Web Application Security Project® (OWASP)

#### A01:2021
##### Url=https://owasp.org/Top10/A01_2021-Broken_Access_Control/
##### Description
  Broken Access Control

#### A02:2021
##### Url=https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
##### Description
  Cryptographic Failures

#### A03:2021
##### Url=https://owasp.org/Top10/A03_2021-Injection/
##### Description
  Injection

#### A04:2021
##### Url=https://owasp.org/Top10/A04_2021-Insecure_Design/
##### Description
  Insecure Design

#### A05:2021
##### Url=https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
##### Description
  Security Misconfiguration

#### A08:2021
##### Url=https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
##### Description
  Software and Data Integrity Failures

#### A10:2017
##### Url=https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring
##### Description
  Insufficient Logging & Monitoring

#### A4:2007
##### Url=https://wiki.owasp.org/index.php/Top_10_2007-Insecure_Direct_Object_Reference
##### Description
  Insecure Direct Object Reference

#### A7:2004
##### Url=https://owasp.org/www-community/Improper_Error_Handling
##### Description
  Improper Error Handling

### SEI CERT
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java
##### Description
  SEI CERT Oracle Coding Standard for Java

#### ERR07-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/ERR07-J.+Do+not+throw+RuntimeException%2C+Exception%2C+or+Throwable
##### Description
  Do not throw RuntimeException, Exception, or Throwable

#### ERR08-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/ERR08-J.+Do+not+catch+NullPointerException+or+any+of+its+ancestors
##### Description
  Do not catch NullPointerException or any of its ancestors

#### ERR51-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/ERR51-J.+Prefer+user-defined+exceptions+over+more+general+exception+types
##### Description
  Prefer user-defined exceptions over more general exception types

#### EXP01-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/EXP01-J.+Do+not+use+a+null+in+a+case+where+an+object+is+required
##### Description
  Do not use a null in a case where an object is required

#### EXP50-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/EXP50-J.+Do+not+confuse+abstract+object+equality+with+reference+equality
##### Description
  Do not confuse abstract object equality with reference equality

#### EXP52-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/EXP52-J.+Use+braces+for+the+body+of+an+if%2C+for%2C+or+while+statement
##### Description
  Use braces for the body of an if, for, or while statement

#### FIO16-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them
##### Description
  Canonicalize path names before validating them

#### IDS00-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS00-J.+Prevent+SQL+injection
##### Description
  Prevent SQL injection

#### IDS02-j
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS02-J.+Canonicalize+path+names+before+validating+them
##### Description
  Canonicalize path names before validating them

#### IDS07-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method
##### Description
  Sanitize untrusted data passed to the Runtime.exec() method

#### IDS15-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS15-J.+Do+not+allow+sensitive+information+to+leak+outside+a+trust+boundary
##### Description
  Do not allow sensitive information to leak outside a trust boundary

#### IDS51-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS51-J.+Properly+encode+or+escape+output
##### Description
  Properly encode or escape output

#### IDS52-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS52-J.+Prevent+code+injection
#### IDS53-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS53-J.+Prevent+XPath+Injection
##### Description
  Prevent code injection

#### IDS54-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/IDS54-J.+Prevent+LDAP+injection
#### LCK05-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/LCK05-J.+Synchronize+access+to+static+fields+that+can+be+modified+by+untrusted+code
##### Description
  Synchronize access to static fields that can be modified by untrusted code

#### MSC03-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/MSC03-J.+Never+hard+code+sensitive+information
##### Description
  Never hard code sensitive information

#### MSC52-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/MSC52-J.+Finish+every+set+of+statements+associated+with+a+case+label+with+a+break+statement
##### Description
  Finish every set of statements associated with a case label with a break statement

#### MSC61-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+use+insecure+or+weak+cryptographic+algorithms
##### Description
  Prevent LDAP injection

#### MSC62-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/MSC62-J.+Store+passwords+using+a+hash+function
##### Description
  Store passwords using a hash function

#### MSC63-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/MSC63-J.+Ensure+that+SecureRandom+is+properly+seeded
##### Description
  Ensure that SecureRandom is properly seeded

#### OBJ01-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ01-J.+Limit+accessibility+of+fields
##### Description
  Limit accessibility of fields

#### OBJ04-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ04-J.+Provide+mutable+classes+with+copy+functionality+to+safely+allow+passing+instances+to+untrusted+code
##### Description
  Provide mutable classes with copy functionality to safely allow passing instances to untrusted code

#### OBJ05-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ05-J.+Do+not+return+references+to+private+mutable+class+members
##### Description
  Do not return references to private mutable class members

#### OBJ06-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ06-J.+Defensively+copy+mutable+inputs+and+mutable+internal+components
##### Description
  Defensively copy mutable inputs and mutable internal components

#### OBJ08-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ08-J.+Do+not+expose+private+members+of+an+outer+class+from+within+a+nested+class
##### Description
  Do not expose private members of an outer class from within a nested class

#### OBJ10-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ10-J.+Do+not+use+public+static+nonfinal+fields
##### Description
  Do not use public static nonfinal fields

#### OBJ13-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/OBJ13-J.+Ensure+that+references+to+mutable+objects+are+not+exposed
##### Description
  Ensure that references to mutable objects are not exposed

#### SEC00-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/SEC00-J.+Do+not+allow+privileged+blocks+to+leak+sensitive+information+across+a+trust+boundary
##### Description
  Do not allow privileged blocks to leak sensitive information across a trust boundary

#### SEC03-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/SEC03-J.+Do+not+load+trusted+classes+after+allowing+untrusted+code+to+load+arbitrary+classes
##### Description
  Do not load trusted classes after allowing untrusted code to load arbitrary classes

#### SEC52-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/SEC52-J.+Do+not+expose+methods+that+use+reduced-security+checks+to+untrusted+code
##### Description
  Do not expose methods that use reduced-security checks to untrusted code

#### STR02-J
##### Url=https://wiki.sei.cmu.edu/confluence/display/java/STR02-J.+Specify+an+appropriate+locale+when+comparing+locale-dependent+data
##### Description
  Specify an appropriate locale when comparing locale-dependent data

## general
### Best Practice Rules
##### Summarized=true
##### Description
  Rules which enforce generally accepted best practices.

### Code Style Rules
##### Summarized=true
##### Description
  Rules which enforce a specific coding style.

### Design Rules
##### Summarized=true
##### Description
  Rules that help you discover design issues.

### Documentation Rules
##### Summarized=true
##### Description
  Rules that are related to code documentation.

### Error Prone Rules
##### Summarized=true
##### Description
  Rules to detect constructs that are either broken, extremely confusing or prone to runtime errors.

### Multithreading Rules
##### Summarized=true
##### Description
  Rules that flag issues when dealing with multiple threads of execution.

### Performance Rules
##### Summarized=true
##### Description
  Rules that flag suboptimal code.

# Metrics
## FH_ACNPE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Catching NPE
#### WarningText
  Avoid catching NullPointerException; consider removing the cause of the NPE.

#### HelpText
  Code should never throw NullPointerExceptions under normal circumstances. A catch block may hide the original error, causing other, more subtle problems later on.

  Example(s):

  ``` java
  public class Foo {

    void bar() {
      try {
      // do something
      } catch (NullPointerException npe) {
      
      }
    }
  }
  ```

#### Tags
- /collection/CWE/395
- /collection/CWE/690
- /collection/OWASP/A7:2004
- /collection/SEI CERT/ERR08-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_ACT
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Catching Throwable
#### WarningText
  A catch statement should never catch throwable since it includes errors.

#### HelpText
  Catching Throwable errors is not recommended since its scope is very broad. It includes runtime issues such as OutOfMemoryError that should be exposed and managed separately.

  Example(s):

  ``` java
  public void bar() {
    try {
      // do something
    } catch (Throwable th) { // should not catch Throwable
      th.printStackTrace();
    }
  }
  ```

#### Tags
- /collection/CWE/397
- /collection/CWE/7
- /collection/CWE/754
- /collection/SEI CERT/ERR07-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ADNIS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Deeply Nested If Stmts
#### WarningText
  Deeply nested if..then statements are hard to read. They can make the source code less readable.

#### HelpText
  Avoid creating deeply nested if-then statements since they are harder to read and error-prone to maintain.

  Example(s):

  ``` java
  public class Foo {

    public void bar(int x, int y, int z) {
      if (x > y) {
        if (y > z) {
          if (z == x) {
            // !! too deep
          }
        }
      }
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_AES
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Add Empty String
#### WarningText
  Do not add empty strings.

#### HelpText
  The conversion of literals to strings by concatenating them with empty strings is inefficient. It is much better to use one of the type-specific toString() methods instead.

  Example(s):

  ``` java
  String s = "" + 123; // inefficient

  String t = Integer.toString(456); // preferred approach
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_AICICC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Instanceof Checks In Catch Clause
#### WarningText
  An instanceof check is being performed on the caught exception.  Create a separate catch clause for this exception type.

#### HelpText
  Each caught exception type should be handled in its own catch clause.

  Example(s):

  ``` java
  try { // Avoid this
    // do something
  } catch (Exception ee) {
    if (ee instanceof IOException) {
      cleanup();
    }
  }

  try { // Prefer this:
    // do something
  } catch (IOException ee) {
    cleanup();
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_AIO
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Assignment In Operand
#### WarningText
  Avoid using assignment operators in operands.

#### HelpText
  Avoid Assignments in operands; this can make code more complicated and harder to read.

  Example(s):

  ``` java
  public class Foo {

    public void bar(int x, int y, int z) {
      if ((x = y) > 6) { // assignment operator in condition
        z = 9;
      }
    }

  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_AISD
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Array Is Stored Directly
#### WarningText
  The user-supplied array is stored directly.

#### HelpText
  Constructors and methods receiving arrays should clone objects and store the copy. This prevents future changes from the user from affecting the original array.

  Example(s):

  ``` java
  public class Foo {

    private String [] x;
    
    public void foo (String [] param) {
      // Don't do this, make a copy of the array at least
      this.x=param;
    }
  }
  ```

#### Tags
- /collection/CWE/496
- /collection/OWASP/A4:2007
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ALOC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=At Least One Constructor
#### WarningText
  Each class should declare at least one constructor.

#### HelpText
  Each class should declare at least one constructor.
  Example(s):

  ``` java
    
  public class Foo {
     // missing constructor
    public void doSomething() { ... }
    public void doOtherThing { ... }
  }
    
    
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_APST
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Print Stack Trace
#### WarningText
  Avoid printStackTrace(); use a logger call instead.

#### HelpText
  Avoid printStackTrace(); use a logger call instead.

  Example(s):

  ``` java
  class Foo {

    void bar() {
      try {
        // do something
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ARE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Rethrowing Exception
#### WarningText
  A catch statement that catches an exception only to rethrow it should be avoided.

#### HelpText
  Catch blocks that merely rethrow a caught exception only add to code size and runtime complexity. In cases when the rethrowed exception can be caught by following catches are allowed.

  Example(s):

  ``` java
  public void bar() {
    try {
      / do something
    } catch (SomeException se) {
      throw se;
    }
  }

  public void foo(int a) throws IOException {
    try {
      if(a == 20) {
        throw new IOException();
      }
    } catch (IOException e) {
      throw e; // this is pointless
    }
  }
    
    public void goo(int a) throws IOException {
      try {
        if(a == 20) {
          throw new IOException();
        } else {
          throw new Eception();
        }
      } catch(IOException e) {
        throw e; // it's OK, we don't want to catch the IOException here.
      } catch(Exception e){
      // do something
      }
    }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ATNPE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Throwing Null Pointer Exception
#### WarningText
  Avoid throwing null pointer exceptions.

#### HelpText
  Avoid throwing NullPointerExceptions. These are confusing because most people will assume that the virtual machine threw it. Consider using an IllegalArgumentException instead; this will be clearly seen as a programmer-initiated exception. The rule also warns on null pointer exception instantiations.

  Example(s):

  ``` java
  public class Foo {

    void bar() {
      throw new NullPointerException();
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_ATRET
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Avoid Throwing Raw Exception Types
#### WarningText
  Avoid throwing raw exception types.

#### HelpText
  Avoid throwing certain exception types. Rather than throw a raw RuntimeException, Throwable, Exception, or Error, use a subclassed exception or error instead. The rule also warns on raw exception instantiations.

  Example(s):

  ``` java
  public class Foo {

    public void bar() throws Exception {
      throw new Exception();
    }
  }
  ```

#### Tags
- /collection/CWE/397
- /collection/SEI CERT/ERR07-J
- /collection/SEI CERT/ERR51-J
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_BGMN
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Boolean Get Method Name
#### WarningText
  A 'getX()' method which returns a boolean should be named 'isX()'.

#### HelpText
  Methods that return boolean results should be named as predicate statements to denote this. I.e, ‘isReady()’, ‘hasValues()’, ‘canCommit()’, ‘willFail()’, etc. Avoid the use of the ‘get’ prefix for these methods.

  Example(s):

  ``` java
  public boolean getFoo(); // bad

  public boolean isFoo(); // ok

  public boolean getFoo(boolean bar); // ok
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_BI
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Boolean Instantiation
#### WarningText
  Avoid instantiating Boolean objects.

#### HelpText
  Avoid instantiating Boolean objects; you can reference Boolean.TRUE, Boolean.FALSE, or call Boolean.valueOf() instead.

  Example(s):

  ``` java
  Boolean bar = new Boolean("true"); // unnecessary creation, just reference Boolean.TRUE;

  Boolean buz = Boolean.valueOf(false); // ..., just reference Boolean.FALSE;
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_BII
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Big Integer Instantiation
#### WarningText
  Don't create instances of already existing BigInteger and BigDecimal (ZERO, ONE, TEN).

#### HelpText
  Don’t create instances of already existing BigInteger (BigInteger.ZERO, BigInteger.ONE) and for Java 1.5 onwards, BigInteger.TEN and BigDecimal (BigDecimal.ZERO, BigDecimal.ONE, BigDecimal.TEN)

  Example(s):

  ``` java
  BigInteger bi = new BigInteger(1); // reference BigInteger.ONE instead

  BigInteger bi2 = new BigInteger("0"); // reference BigInteger.ZERO instead

  BigInteger bi3 = new BigInteger(0.0); // reference BigInteger.ZERO instead

  BigInteger bi4;

  bi4 = new BigInteger(0); // reference BigInteger.ZERO instead
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ByI
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Byte Instantiation
#### WarningText
  Avoid instantiating Byte objects. Call Byte.valueOf() instead.

#### HelpText
  Calling new Byte() causes memory allocation that can be avoided by the static Byte.valueOf(). It makes use of an internal cache that recycles earlier instances making it more memory efficient.

  Example(s):

  ``` java
  public class Foo {

    private Byte i = new Byte(0); // change to Byte i = Byte.valueOf(0);
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_CC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Cyclomatic Complexity
#### WarningText
  The method has greater Cyclomatic Complexity than the limit.

#### HelpText
  Complexity of the method expressed as the number of independent control flow paths in it. It represents a lower bound for the number of possible execution paths in the source code and at the same time it is an upper bound for the minimum number of test cases needed for achieving full branch test coverage. The value of the metric is initially 1 which increases by 1 for each occurence of the following instructions: if, for, foreach, while, do-while, case label (label that belongs to a switch instruction), catch (handler that belongs to a try block), conditional statement (?:). Moreover, logical and (&&) and logical or (||) expressions also add to the final value because their short-circuit evalutaion can cause branching depending on the first operand. The following language elements do not increase the value: else, try, switch, default label (default label that belongs to a switch instruction), finally.
  Example(s):

  ``` java

  public class Foo {      // This has a Cyclomatic Complexity = 11
  1   public void example()  {
  2       if (a == b)  {
  3           if (a1 == b1) {
                  fiddle();
  4           } else if a2 == b2) {
                  fiddle();
              }  else {
                  fiddle();
              }
  5       } else if (c == d) {
  6           while (c == d) {
                  fiddle();
              }
  7        } else if (e == f) {
  8           for (int n = 0; n < h; n++) {
                  fiddle();
              }
          } else{
              switch (z) {
  9               case 1:
                      fiddle();
                      break;
  10              case 2:
                      fiddle();
                      break;
  11              case 3:
                      fiddle();
                      break;
                  default:
                      fiddle();
                      break;
              }
          }
      }
  }

     
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_CEPSHJSRV
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Controller endpoint parameter JSR validation
#### WarningText
  Parameters of controllers endpoints should have JSR validation.

#### HelpText
  Functions in controller classes, which act as controller endpoints should have their parameters validated with JSR validation annotations, like <span class="citation" data-cites="NotNull">@NotNull</span>, <span class="citation" data-cites="Min">@Min</span>, <span class="citation" data-cites="Max">@Max</span>, etc.

  ``` java
  public class ExampleController {
    @GetMapping
    int getEndpointWithEntityParameter(@Valid ExampleEntity testEntity) {
      //Implementation...
    }

    @PostMapping
    public int postEndpointWithParameter(@NotNull String str) {
      //Implementation...
    }

    @RequestMapping
    public int requestEndpointMoreParameter(@Positive int db, @PositiveOrZero int count) {
      //Implementation...
    } 

    @DeleteMapping
    public int deleteEndpointMoreParameter(@Negative int num, @NegativeOrZero int num2) {
      //Implementation...
    } 

    @PutMapping
    public int putEndpointMoreParameter(@PastOrPresent Date startDate, @FutureOrPresent Date endDate) {
      //Implementation...
    } 

    @PatchMapping
    public int patchEndpointParameter(@NotNull ControllerTmp test) {
      //Implementation...
    } 
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_COWE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Compare Objects With Equals
#### WarningText
  Use equals() to compare object references.

#### HelpText
  Use equals() to compare object references; avoid comparing them with == or !=.
  Example(s):

  ``` java

  class Foo {
    boolean bar(String a, String b) {
      return a == b;
    }
  }


    
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_CSBVA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Controller @Validated annotation
#### WarningText
  Avoid @Controller or @RestController annotation without @Validated annotation.

#### HelpText
  Controller classes should have <span class="citation" data-cites="Validated">@Validated</span> annotation in addition to the <span class="citation" data-cites="Controller">@Controller</span> or <span class="citation" data-cites="RestController">@RestController</span> annotations.

  ``` java
  @Validated
  @Controller
  public class ExamplesControllerValidated {
  }

  @Validated
  @RestController
  public class ExampleRestControllerValidated {
  }

  //Wrong! Do not do the following two.
  @Controller
  public class ControllerValidateFailed {
  }

  @RestController
  public class RestControllerValidateFailed {
  } 
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ClR
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Close Resource
#### WarningText
  Ensure that all resources object are closed after use.

#### HelpText
  Ensure that resources (like Connection, Statement, and ResultSet objects) are always closed in a finally block after use.

  Example(s):

  ``` java
  public class Bar {

    public void foo() {
      Connection c = pool.getConnection();
      try {
        // do stuff
      } catch (SQLException ex) {
        // handle exception
      } finally {
        // oops, should close the connection using 'close'!
        // c.close();
      }
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_DLNLISS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Default Label Not Last In Switch Stmt
#### WarningText
  The default label should be the last label in a switch statement.

#### HelpText
  By convention, the default label should be the last label in a switch statement.

  Example(s):

  ``` java
  public class Foo {

    void bar(int a) {
      switch (a) {
        case 1: // do something
          break;
        default: // the default case should be last, by convention
          break;
        case 2:
          break;
      }
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_DNCRE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Do not Call Runtime exec
#### WarningText
  Do not Call Runtime exec

#### HelpText
  Runtime.exec() should not be invoked.

  Example(s):

  ``` java
    void executeCommand(String command) {
      Process process = Runtime.getRuntime().exec(command);
      // ...
    }
  ```

#### Tags
- /collection/CWE/78
- /collection/OWASP/A03:2021
- /collection/SEI CERT/IDS07-J
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_DNCTIEJB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Do not Create Threads in EJB
#### WarningText
  Do not Create Threads in EJB

#### HelpText
  The enterprise bean must not attempt to manage threads because it would harm resource management and transaction management.

  Example(s):

  ``` java
  @Stateless
  public class Example {
    void threadExample() {
      Thread t = new Thread();
      t.run();  // never call Thread.run() in EJB
      t.start();  // never call Thread.start() in EJB
    }
    
    void runnableExample() {
      Runnable r = new Runnable() {
        public void run() {
          // ...
        }
      };
      r.run();  // never call Runnable.run() in EJB
    }
    
    void callableExample() throws Exception {
      Callable<Integer> c = new Callable<Integer>() {
        public Integer call() throws Exception {
          // ...
        }
      };
      c.call();  // never call Callable<T>.call() in EJB
    }
  }
  ```

#### Tags
- /general/Multithreading Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_DNULFIEJB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Do not Use Local Files in EJB
#### WarningText
  Do not Use Local Files in EJB

#### HelpText
  java.io.Reader, java.io.InputStream, java.nio.file.Files and javax.imageio.stream.FileImageInputStream should not be used in enterprise bean to access local files.

  Example(s):

  ``` java
  @Remote
  public class Example {
    void foo() {
      Reader reader = new StringReader("input.txt");
      // ...
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_DNUNQA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Do Not Use NamedQuery Annotation
#### WarningText
  Do Not Use NamedQuery Annotation

#### HelpText
  NamedQuery annotations should not be used.

  Example(s):

  ``` java
  @NamedQuery(
      name="findAllEmployee",
      queryString="SELECT * FROM Employee"
  )
  public class Employee {
    // ...
  }


  @NamedQueries({
    @NamedQuery(name="Student.findAll",
                query="SELECT s FROM Student s"),
    @NamedQuery(name="Student.findByName",
                query="SELECT s FROM Student s WHERE s.name = :name")
  })
  public class Student {
    // ...
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_DNUSIEJB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Do not Use Synchronized in EJB
#### WarningText
  Do not Use Synchronized in EJB

#### HelpText
  Neither method nor block level synchronization should be used in enterprise bean.

  Example(s):

  ``` java
  @Stateless
  class Example {
    
    public synchronized void foo() {
      // ...
    }

    public void goo() {
      synchronized(this) {
        // ...
      }
    }
  }
  ```

#### Tags
- /general/Multithreading Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ECB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Catch Block
#### WarningText
  Avoid empty catch blocks.

#### HelpText
  Empty Catch Block finds instances where an exception is caught, but nothing is done, except if there is a comment in the code. In most circumstances, this swallows an exception which should either be acted on or reported.

  Example(s):

  ``` java
  public void doSomething() {
    try {
    FileInputStream fis = new FileInputStream("/tmp/bugger");
    } catch (IOException ioe) {

    }
  }
  ```

#### Tags
- /collection/OWASP/A10:2017
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_EEMNEA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Need @Enumerated annotation
#### WarningText
  Avoid enum member of entity class without @Enumerated annotation.

#### HelpText
  Avoid enum members in an entity class without annotating it with the <span class="citation" data-cites="Enumerated">@Enumerated</span> annotation.

  ``` java
  public class ExampleEntity {
    public enum TestType {
      Test1,
      Test2,
      Test3
    } 

    @Enumerated(value = EnumType.STRING)
    TestType enumMember; 

    @Enumerated(EnumType.STRING)
    TestType enumMember2; 

    //The following ones are incorrect.
    @Enumerated(value = EnumType.ORDINAL)
    TestType wrongAnnotationValue; 

    @Enumerated(value = EnumType.ORDINAL, value = EnumType.STRING)
    TestType wrongAnnotationValueNumber; 

    @Enumerated(EnumType.ORDINAL, EnumType.STRING)
    TestType wrongAnnotationValue2;

    @Enumerated
    TestType missingAnnotationValueEnumMember; 
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EFB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Finally Block
#### WarningText
  Avoid empty finally blocks.

#### HelpText
  Empty finally blocks serve no purpose and should be removed.

  Example(s):

  ``` java
  public class Foo {

    public void bar() {
      try {
      int x=2;
      } finally {
      // empty!
      }
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EIS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty If Stmt
#### WarningText
  Avoid empty 'if' statements.

#### HelpText
  Empty If Statement finds instances where a condition is checked but nothing is done about it.

  Example(s):

  ``` java
  public class Foo {

    void bar(int x) {
      if (x == 0) {
      // empty!
      }
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_EMHEAH
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Need equals and hashcode method
#### WarningText
  Avoid @Entity annotation without equals and hashcode method.

#### HelpText
  Entity classes should override both the equals and the hashcode methods inherited from the Object class.

  ``` java
  public class ExampleEntity {
    @Override
    public boolean equals(Object obj) {
      //Implementation...
    }

    @Override
    public int hashCode() {
      //Implementation...
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EML
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Excessive Method Length
#### WarningText
  Avoid really long methods.

#### HelpText
  When methods are excessively long this usually indicates that the method is doing more than its name/signature might suggest. They also become challenging for others to digest since excessive scrolling causes readers to lose focus. Try to reduce the method length by creating helper methods and removing any copy/pasted code.
  Example(s):

  ``` java

  public void doSomething() {
      System.out.println("Hello world!");
      System.out.println("Hello world!");
          // 98 copies omitted for brevity.
  }


     
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EMRC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Equal Method Returns Constant
#### WarningText
  Avoid using equals() methods with a constant return value.

#### HelpText
  Do not use equals() methods with a constant return value. These are potentially unfinished methods.

  Example(s):

  ``` java
  public class Foo {

  @Override
  public boolean equals(Object arg) {
    return true; // returns with constant
  }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EMSHJSRV
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Entity member JSR validation
#### WarningText
  Members of the entity should have JSR validation annotations.

#### HelpText
  The members of the entity class should have JSR validation, like <span class="citation" data-cites="NotNull">@NotNull</span>, <span class="citation" data-cites="Min">@Min</span>, <span class="citation" data-cites="Max">@Max</span>, etc.

  Example(s):

  ``` java
  public class ExampleEntity {
    @Min(2)
    private int num;

    @Max(10)
    private int db;

    @AssertTrue
    private boolean isTest;

    @AssertFalse
    private boolean isNotTest;

    @NotEmpty
    private List labels;
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ENVMA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Entity optimistic locking
#### WarningText
  Avoid @Entity annotation without version member and annotation.

#### HelpText
  Avoid using the <span class="citation" data-cites="Entity">@Entity</span> annotation on a class without it containing a member annotated with the <span class="citation" data-cites="Version">@Version</span> annotation. The type of this member should be long or Long.

  ``` java
  @Entity
  public class T_EntityVersionSuccess {
    @Version
    private Long version;
    
    public Long getVersion() {
      return version;
    }
  } 
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EOB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Override Block
#### WarningText
  An empty method should not be overridden by another empty method.

#### HelpText
  Do not override an empty method with another empty method. It is useless.

  Example(s):

  ``` java
  public class Foo {

    public void bar() {
    
    }
    
  }

  public class Child extends Foo{

    @Override
    public void bar() { // empty override block

    }
  }
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ESB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Synchronized Block
#### WarningText
  Avoid empty synchronized blocks.

#### HelpText
  Empty synchronized blocks serve no purpose and should be removed.

  Example(s):

  ``` java
  public class Foo {

    public void bar() {
      synchronized (this) {
      // empty!
      }
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ESBVA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=@Entity and @Validated annotation
#### WarningText
  Avoid @Entity annotation without @Validated annotation.

#### HelpText
  Entity classes should have a <span class="citation" data-cites="Validated">@Validated</span> annotation in addition to the <span class="citation" data-cites="Entity">@Entity</span> annotation.

  ``` java
  @Validated
  @Entity
  public class ExampleEntity {
    public ExampleEntity() {}
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ESHPDC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Entity annotation
#### WarningText
  Avoid @Entity annotation without public default constructor.

#### HelpText
  Avoid using <span class="citation" data-cites="Entity">@Entity</span> annotation without a public default constructor in the class. This constructor can either be compiler-generated or explicitly written.

  Example(s):

  ``` java
  @Validated
  @Entity
  public class ExampleEntity {
    public ExampleEntity() {}
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ESS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Switch Statements
#### WarningText
  Avoid empty switch statements.

#### HelpText
  Empty switch statements serve no purpose and should be removed.

  Example(s):

  ``` java
  public void bar() {
    int x = 2;
    switch (x) {
      // once there was code here
      // but it's been commented out or something
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ETB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty Try Block
#### WarningText
  Avoid empty try blocks.

#### HelpText
  Avoid empty try blocks - what’s the point?

  Example(s):

  ``` java
  public class Foo {

    public void bar() {
      try {
      
      } catch (Exception e) {
      e.printStackTrace();
      }
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_EVART
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Entity optimistic locking type
#### WarningText
  The @Version annotation should be on the right type.

#### HelpText
  The <span class="citation" data-cites="Version">@Version</span> annotation in the entity class should be used on the right type. The usable types are: int, Integer, long, Long, short, Short. We recommend using long or Long.

  ``` java
  public class EntityVersionRightType {

    @Version
    private Integer version; //It is OK.

    public Integer getVersion() {
      return version;
    }
  } 

  public class EntityVersionWrongType {

    @Version
    private String version; //Wrong! The version member should be one of the types mentioned above.

    public String getVersion() {
      return version;
    }
  } 
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_EWS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Empty While Stmt
#### WarningText
  Avoid empty 'while' statements.

#### HelpText
  Empty While Statement finds all instances where a while statement does nothing. If it is a timing loop, then you should use Thread.sleep() for it; if it is a while loop that does a lot in the condition expression (increase, decrease, assign or call a method), no warning is issued.

  Example(s):

  ``` java
  void bar(int a, int b) {
    while (a == b) {
      // empty!
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_FLMUB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=For Loops Must Use Braces
#### WarningText
  Avoid using 'for' statements without curly braces.

#### HelpText
  Avoid using ‘for’ statements without using curly braces. If the code formatting or indentation is lost then it becomes difficult to separate the code being controlled from the rest.

  Example(s):

  ``` java
  for (int i = 0; i < 42; i++)
    foo();
  ```

#### Tags
- /collection/SEI CERT/EXP52-J
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_GEHE
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Global exception handler
#### WarningText
  Global exception handler exist.

#### HelpText
  Global exception handler exist.

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_HF
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Hide Field
#### WarningText
  Reach fields via getter/setter functions, not by direct reference

#### HelpText
  Reach fields via getter/setter functions, not by direct reference.

  Example(s):

  ``` java
  public class Foo {

    public int i;

  }

  class Bar {

    public void example() {
      Foo f = new Foo();
      int z = f.i; // should be accessed via a getter
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_IESMUB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=If Else Stmts Must Use Braces
#### WarningText
  Avoid using 'if...else' statements without curly braces.

#### HelpText
  Avoid using if or if..else statements without using surrounding braces. If the code formatting or indentation is lost then it becomes difficult to separate the code being controlled from the rest.

  Example(s):

  ``` java
  if (foo)
    x = x+1;
  else
    x = x-1;
  ```

#### Tags
- /collection/SEI CERT/EXP52-J
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_II
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Integer Instantiation
#### WarningText
  Avoid instantiating Integer objects. Call Integer.valueOf() instead.

#### HelpText
  Calling new Integer() causes memory allocation that can be avoided by the static Integer.valueOf(). It makes use of an internal cache that recycles earlier instances making it more memory efficient.

  Example(s):

  ``` java
  public class Foo {

    private Integer i = new Integer(0);
    // change to Integer i = Integer.valueOf(0);
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_JSRVART
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=JSR validation type
#### WarningText
  JSR validation annotations should be used on the right type.

#### HelpText
  The given annotation is not working properly with the type it was used on. For example, make sure you use annotations like <span class="citation" data-cites="Min">@Min</span> and <span class="citation" data-cites="Max">@Max</span> on numeric values and <span class="citation" data-cites="AssertTrue">@AssertTrue</span> and <span class="citation" data-cites="AssertFalse">@AssertFalse</span> annotations on boolean values.

  Example(s):

  ``` java
  int getRightMinParameter(@Min(7) int id) { //It is OK, because id is an integer.
    return 1;
  }

  int getRightAsserTrueParameter(@AssertTrue boolean conditionValue) { //It is also OK, @AssertTrue is on a boolean value.
    return 1;
  }

  int getWrongMinPrimitiveType(@Min(7) boolean id) { //Wrong! The @Min annotation should be used on an integer value like above.
    return 1;
  }

  int getWrongAsserTruePrimitiveParameter(@AssertTrue int conditionValue) { //Wrong! The @AssertTrue annotation should be used on a boolean value.
    return 1;
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_LVCBF
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Local Variable Could Be Final
#### WarningText
  Local variable could be declared final.

#### HelpText
  A local variable assigned only once can be declared final.
  Example(s):

  ``` java
    
  public class Bar {
      public void foo () {
          String txtA = "a";      // if txtA will not be assigned again it is better to do this:
          final String txtB = "b";
      }
  }
    
        
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_LoC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Loose Coupling
#### WarningText
  Avoid using concrete implementation types. Use its interface instead.

#### HelpText
  Avoid using implementation types (i.e., HashSet); use the interface (i.e, Set) instead.

  Example(s):

  ``` java
  import java.util.ArrayList;
  import java.util.HashSet;

  public class Bar {
    // Use List instead
    private ArrayList list = new ArrayList();
    
    // Use Set instead
    public HashSet getFoo() {
      return new HashSet();
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_LoI
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Long Instantiation
#### WarningText
  Avoid instantiating Long objects.Call Long.valueOf() instead.

#### HelpText
  Calling new Long() causes memory allocation that can be avoided by the static Long.valueOf(). It makes use of an internal cache that recycles earlier instances making it more memory efficient.

  Example(s):

  ``` java
  public class Foo {

    private Long i = new Long(0); // change to Long i = Long.valueOf(0);
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_MBIS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Missing Break In Switch
#### WarningText
  A switch statement does not contain a break.

#### HelpText
  Switch statements without break, continue, throw or return statements for each case branch may indicate problematic behaviour. Empty cases are ignored as these indicate an intentional fall-through. When the case branch ends with a comment with ‘fall-through’ content are ignored as well. Missing break in the last case branch does not cause any problem so it is also ignored.

  Example(s):

  ``` java
  public void bar(int status) {
    switch(status) {
      case CANCELLED:
        doCancelled();
        // break; hm, should this be commented out?
      case NEW:
        doNew();
        // is this really a fall-through?
      case REMOVED:
        doRemoved();
        // what happens if you add another case after this one?
      case OTHER: // empty case - this is interpreted as an intentional
        // fall-through
      case ERROR:
        doErrorHandling();
        break;
    }
  }
  ```

#### Tags
- /collection/SEI CERT/MSC52-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_MNCTS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Missing Null Check In ToString
#### WarningText
  Avoid using an object's members in toString methods without checking whether the object is null.

#### HelpText
  Avoid using an object’s members in toString methods without checking whether the object is null. A null check may be required to avoid NullPointerException.

  Example(s):

  ``` java
  public class Foo {

    private Object o;

    @Override
    public String toString() {
      return o.toString(); // missing null check
    }
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_MWSNAEC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Method With Same Name As Enclosing Class
#### WarningText
  Classes should not have non-constructor methods with the same name as the class.

#### HelpText
  Non-constructor methods should not have the same name as the enclosing class.

  Example(s):

  ``` java
  public class MyClass {

    public MyClass() {} // this is OK because it is a constructor
    public void MyClass() {} // this is bad because it is a method
  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_MeNC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Method Naming Conventions
#### WarningText
  Method name does not begin with a lower case character.

#### HelpText
  Method names should always begin with a lower case character, and should not contain underscores.

  Example(s):

  ``` java
  public class Foo {

    public void fooStuff() {

    }

  }
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_NFSVMBSB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Non Final Static Variable Must Be In Synchronized Block
#### WarningText
  Non-constant static variable must be used in synchronized block or method.

#### HelpText
  Non-constant static variable must be used in synchronized block or method.

  Example(s):

  ``` java
  public class Foo {

    public static int a;

    public void bar() { // should be synchronized
      if (a == 0){
        a = 10;
      }
    }
  }
  ```

#### Tags
- /collection/CWE/820
- /collection/SEI CERT/LCK05-J
- /general/Multithreading Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_NPC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=NPath Complexity
#### WarningText
  The method has greater NPath complexity than the limit.

#### HelpText
  The NPath complexity of a method is the number of acyclic execution paths through that method. A threshold of 200 is generally considered the point where measures should be taken to reduce complexity and increase readability.
  Example(s):

  ``` java
   
  void bar() {    // this is something more complex than it needs to be,
      if (y) {    // it should be broken down into smaller methods or functions
          for (j = 0; j < m; j++) {
              if (j > r) {
                  doSomething();
                  while (f < 5 ) {
                      anotherThing();
                      f -= 27;
                      }
                  } else {
                      tryThis();
                  }
              }
          }
          if ( r - n > 45) {
             while (doMagic()) {
                findRabbits();
             }
          }
          try {
              doSomethingDangerous();
          } catch (Exception ex) {
              makeAmends();
              } finally {
                  dontDoItAgain();
                  }
      }
  }

   
      
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_PLFIC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Position Literals First In Comparisons
#### WarningText
  Position literals first in String comparisons.

#### HelpText
  Position literals (or static final variables) first in comparisons, if the second argument is null then NullPointerExceptions can be avoided, they will just return false.

  Example(s):

  ``` java
  class Foo {

    private static final String OK_BUTTON = "OK";

    boolean bar(String x) {
      return x.equals("2"); // should be "2".equals(x)
    }

    boolean isOK(String x) {
      return x.equals(OK_BUTTON); // should be OK_BUTTON.equals(x)
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_PLFICIC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Position Literals First In Case Insensitive Comparisons
#### WarningText
  Position literals first in String comparisons for EqualsIgnoreCase

#### HelpText
  Position literals (or static final variables) first in comparisons, if the second argument is null then NullPointerExceptions can be avoided, they will just return false.

  Example(s):

  ``` java
  class Foo {

    private static final String OK_BUTTON = "OK";

    boolean bar(String x) {
      // should be "Bar".equalsIgnoreCase(x)
      return x.equalsIgnoreCase("Bar");
    }

    boolean isOK(String x) {
      // should be OK_BUTTON.equalsIgnoreCase(x)
      return x.equalsIgnoreCase(OK_BUTTON);
    }

  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_PST
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Preserve Stack Trace
#### WarningText
  New exception is thrown in catch block, original stack trace may be lost.

#### HelpText
  Throwing a new exception from a catch block without passing the original exception into the new exception will cause the original stack trace to be lost making it difficult to debug effectively.

  Example(s):

  ``` java
  public class Foo {

    void good() {
      try{
        Integer.parseInt("a");
      } catch (Exception e) {
        throw new Exception(e); // first possibility to create
        // exception chain
      }
      try {
        Integer.parseInt("a");
      } catch (Exception e) {
      throw (IllegalStateException)new IllegalStateException()
        .initCause(e);// second possibility to create exception chain.
      }
    }
    
    void bad() {
      try{
        Integer.parseInt("a");
      } catch (Exception e) {
        throw new Exception(e.getMessage()); // loosing the stack trace!
      }
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_RFRO
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Repository function should return Optional
#### WarningText
  The repository functions should return Optional if the return type is not a collection.

#### HelpText
  The repository functions should return Optional if the return type is not a collection.

  ``` java
  public interface ExampleRepository() {
    ExampleEntity findByFirstName(String firstName); //Wrong! Do not do it.
    
    //Use this one instead.
    Optional findByFirstName(String firstName);

    List findAllByFirstName(String firstName);
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_RHWM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Replace Hashtable With Map
#### WarningText
  Consider replacing this Hashtable with the newer java.util.Map.

#### HelpText
  Consider replacing Hashtable usage with the newer java.util.Map if thread safety is not required.

  Example(s):

  ``` java
  public class Foo {

    void bar() {
      Hashtable h = new Hashtable();
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_RVWL
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Replace Vector With List
#### WarningText
  Consider replacing this Vector with the newer java.util.List.

#### HelpText
  Consider replacing Vector usages with the newer java.util.ArrayList if expensive thread-safe operations are not required.

  Example(s):

  ``` java
  public class Foo {

    void bar() {
      Vector v = new Vector();
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Simplify Conditional
#### WarningText
  No need to check for null before an instanceof.

#### HelpText
  No need to check for null before an instanceof; the instanceof keyword returns false when given a null argument.

  Example(s):

  ``` java
  class Foo {

    void bar(Object x) {
      if (x != null && x instanceof Bar) {
        // just drop the "x != null" check
      }
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SDFNL
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Simple Date Format Needs Locale
#### WarningText
  When instantiating a SimpleDateFormat object, specify a Locale.

#### HelpText
  Be sure to specify a Locale when creating java.text.SimpleDateFormat instances to ensure that locale-appropriate formatting is used.

  Example(s):

  ``` java
  public class Foo {

    // Should specify Locale.US (or whatever)
    private SimpleDateFormat sdf = new SimpleDateFormat("pattern");
  }
  ```

#### Tags
- /collection/SEI CERT/STR02-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SFHEPTTM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Service entity parameter transactional mandatory
#### WarningText
  Service function with entity parameter is missing @Transactional annotation.

#### HelpText
  If a service function has an entity as its parameter, the function should have <span class="citation" data-cites="Transactional">@Transactional</span>(Propagation.MANDATORY) annotation.

  ``` java
  public class ExampleService {
    @Transactional //No entity parameter, @Transactional is enough.
    public void serviceFunctionWithoutEntity(@NotBlank String str) {
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void serviceFunctionWithEntityRight(@NotBlank String str, @NotNull ExampleEntity testEntity) {
    }

    @Transactional(propagation = Propagation.MANDATORY) //There is no entity parameter so according to the rule, this is unnecessary.
    public void serviceFunctionWithEntityWrong3(@NotBlank String str, @NotEmpty List testEntityList) {
      this.privateFunctionWithParameter();
    } 
    
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_SFPSHJSRV
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Service function JSR validation
#### WarningText
  Parameters of service functions should have JSR validation annotations.

#### HelpText
  The parameters of a service function should have been validated with JSR validations like <span class="citation" data-cites="NotNull">@NotNull</span>, <span class="citation" data-cites="Min">@Min</span>, <span class="citation" data-cites="Max">@Max</span>, <span class="citation" data-cites="NotEmpty">@NotEmpty</span>, etc.

  ``` java
  public class ExampleService {
    @Transactional
    public void serviceFunctionWithValidation(@NotBlank String str, @Min(4) Integer num) {
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SFSHT
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Service function @Transactional annotation
#### WarningText
  Service functions should have @Transactional annotation.

#### HelpText
  If a function is used as a service function in a service class, it should be annotated with the <span class="citation" data-cites="Transactional">@Transactional</span> annotation.

  ``` java
  public class ExampleService {
    @Transactional
    public void serviceFunctionWithoutParameter() {
    }

    @Transactional
    public void serviceFunctionWithParameter(@NotBlank String str) {
    }

    //This is not a service function in this case, it does not need the @Transactional annotation.
    private void privatecFunctionWithoutParameter() {
      staticFunctionWithoutParameter();
    }  
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_SHMN
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Suspicious Hashcode Method Name
#### WarningText
  The method name and return type are suspiciously close to hashCode().

#### HelpText
  The method name and return type are suspiciously close to hashCode(), which may denote an intention to override the hashCode() method.

  Example(s):

  ``` java
  public class Foo {

    public int hashcode() { 
      // oops, this probably was
      // supposed to be 'hashCode'
    }

  }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_SI
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Short Instantiation
#### WarningText
  Avoid instantiating Short objects. Call Short.valueOf() instead.

#### HelpText
  Calling new Short() causes memory allocation that can be avoided by the static Short.valueOf(). It makes use of an internal cache that recycles earlier instances making it more memory efficient.

  Example(s):

  ``` java
  public class Foo {

    private Short i = new Short(0); // change to Short i = Short.valueOf(0);
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SMN
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Short Method Name
#### WarningText
  Avoid using short method names.

#### HelpText
  Method names that are very short are not helpful to the reader. Names like ‘or’, ‘in’, ‘lt’, ‘gt’, ‘eq’, ‘le’, ‘ge’, ‘ne’ are allowed.

  Example(s):

  ``` java
  public class ShortMethod {

    public void a( int i ) { // Violation

    }
  }
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SNUAS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Service uses service
#### WarningText
  A service should not use another service.

#### HelpText
  A service should not use another service either as its member or as a parameter for one of its functions.

  ``` java
  public class AnotherService {
    //Some methods here for the service class.
  }

  public class ExampleService {
    private AnotherService anotherService; //Wrong! Another service as a member is not recommended.
    
    //Wrong! Another service as a parameter for a function is not recommended.
    public void serviceFuntionWithServiceParameter(@NotBlank String strParameter, @NotNull AnotherService service) {
    } 
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SP
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=System Println
#### WarningText
  System.(out|err).print is used

#### HelpText
  Printing to System.(out|err) is usually intended for debugging purposes and should not remain in the code.

  Example(s):

  ``` java
  public class Foo {

    Logger log = Logger.getLogger(Foo.class.getName());

    public void testA() {

      System.out.println("Entering");

      // Better use this

      log.info("Entering");

    }

  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SSBVA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Service @Validated annotation
#### WarningText
  Avoid @Service annotation without @Validated annotation.

#### HelpText
  Service classes should have both <span class="citation" data-cites="Service">@Service</span> and <span class="citation" data-cites="Validated">@Validated</span> annotations.

  ``` java
  @Validated
  @Service
  public class ServiceValidation { //OK.
  }

  @Service
  final class ServiceWithoutValidation { //@Validated annotation is missing!
  }

  final class ServiceValidationSimpleClass { //@Service and @Validated annotations are missing! 
  } 
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_SSSHD
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Switch Stmts Should Have Default
#### WarningText
  Switch statements should have a default label.

#### HelpText
  All switch statements should include a default option to catch any unspecified values.

  Example(s):

  ``` java
  public void bar() {
    int x = 2;
    switch (x) {
    case 1: int j = 6;
    case 2: int j = 8;
      // missing default: here
    }
  }
  ```

#### Tags
- /collection/CWE/478
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_TMM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Too Many Methods
#### WarningText
  This class has too many methods, consider refactoring it.

#### HelpText
  A class with too many methods is probably a good suspect for refactoring, in order to reduce its complexity and find a way to have more fine grained objects.

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_TMR
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Too Many Returns
#### WarningText
  Avoid using more than one return statements in a method.

#### HelpText
  Do not use more than one return statement in a method. Too many return statements can make a method less understandable.

  Example(s):

  ``` java
  public class Foo {

    public void bar(int x, int y, int z) { // too many returns
      if (x > y && x > z) {
        return x;
      } else if (y > x && y > z) {
        return y;
      } else {
        return z;
      }
    }
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_UALIOV
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Use Array List Instead Of Vector
#### WarningText
  Use ArrayList instead of Vector.

#### HelpText
  ArrayList is a much better Collection implementation than Vector if thread-safe operation is not required.

  Example(s):

  ``` java
  public class SimpleTest extends TestCase {

    public void testX() {
      Collection c1 = new Vector();
      Collection c2 = new ArrayList(); // achieves the same
      // with much better performance
    }
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_UEM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Uncommented Empty Method
#### WarningText
  Document empty method.

#### HelpText
  Uncommented Empty Method finds instances where a method does not contain statements, but there is no comment. By explicitly commenting empty methods it is easier to distinguish between intentional (commented) and unintentional empty methods.

  Example(s):

  ``` java
  public void doSomething() {

  }
  ```

#### Tags
- /general/Documentation Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_UETCS
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Use Equals To Compare Strings
#### WarningText
  Using the == or != operator is compare the objects with theirs reference. It causes compare beetween two String with equal content returns false.

#### HelpText
  Using ‘==’ or ‘!=’ to compare strings only works if intern version is used on both sides. Use the equals() method instead.

  Example(s):

  ``` java
  public boolean test(String s) {
    if (s == "one") return true; // unreliable
    if ("two".equals(s)) return true; // better
    return false;
  }
  ```

#### Tags
- /collection/CWE/595
- /collection/CWE/597
- /collection/SEI CERT/EXP50-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_ULBR
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Unnecessary Local Before Return
#### WarningText
  Consider simply returning the value vs storing it in a local variable.

#### HelpText
  Consider simply returning the value vs storing it in a local variable.

  Example(s):

  ``` java
  public class Foo {

    public int foo() {
      int x = doSomething();
      return x; // instead, just 'return doSomething();'
    }
  }
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_ULV
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Unused Local Variable
#### WarningText
  Avoid unused local variables.

#### HelpText
  Detects when a local variable is just declared, but not used.

  Example(s):

  ``` java
  public class Foo {

    public void doSomething() {
      int i = 5; // Unused
    }
  }
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_ULWCC
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Use Locale With Case Conversions
#### WarningText
  When doing a String.toLowerCase()/toUpperCase() call, use a Locale.

#### HelpText
  When doing String.toLowerCase()/toUpperCase() conversions, use Locales to avoid problems with languages that have unusual conventions, i.e. Turkish.

  Example(s):

  ``` java
  class Foo {
    // BAD
    if (x.toLowerCase().equals("list"))...
    // This will not match "LIST" when in Turkish locale
    // The above could be
    // if (x.toLowerCase(Locale.US).equals("list")) ...
    // or simply
    // if (x.equalsIgnoreCase("list")) ...
    // GOOD

    String z = a.toLowerCase(Locale.EN);
  }
  ```

#### Tags
- /collection/SEI CERT/STR02-J
- /general/Error Prone Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Critical


## FH_UOM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Useless Overriding Method
#### WarningText
  Avoid method which only calls the method it overrides.

#### HelpText
  The overriding method merely calls the same method defined in a superclass.

  Example(s):

  ``` java
  public void foo(String bar) {
    super.foo(bar); // why bother overriding?
  }

  public String foo() {
    return super.foo(); // why bother overriding?
  }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_UPF
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Unused Private Field
#### WarningText
  Avoid unused private fields.

#### HelpText
  Detects when a private field is just declared, but not used.

  Example(s):

  ``` java
  public class Something {

    private static int FOO = 2; // Unused
    private int i = 5; // Unused
    private int j = 6;
    
    public int addOne() {
      return j++;
    }
  }
  ```

#### Tags
- /collection/CWE/563
- /collection/CWE/886
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_UPM
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Unused Private Method
#### WarningText
  Avoid unused private methods.

#### HelpText
  **Unused Private Method**: Unused Private Method detects when a private method is declared but is unused.

  Example(s):

  ``` java
    public class Something {
      private void foo() {} // unused
    }
    
  ```

#### Tags
- /collection/CWE/563
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_USBFSA
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Use String Buffer For String Appends
#### WarningText
  Prefer StringBuffer over += for concatenating strings.

#### HelpText
  The use of the ‘+=’ operator for appending strings causes the JVM to create and use an internal StringBuffer. If a non-trivial number of these concatenations are being used then the explicit use of a StringBuilder or threadsafe StringBuffer is recommended to avoid this.

  Example(s):

  ``` java
  public class Foo {

    void bar() {
      String a;
      a = "foo";
      a += " bar";
      // better would be:
      // StringBuilder a = new StringBuilder("foo");
      // a.append(" bar");
    }
  }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Major


## FH_UnI
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Unused Imports
#### WarningText
  Avoid unused imports.

#### HelpText
  Avoid unused import statements. This rule will find unused on demand imports, i.e. import com.foo.\*

  Example(s):

  ``` java
  import java.io.*; // not referenced or required

  public class Foo {}
  ```

#### Tags
- /general/Best Practice Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_UsP
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Useless Parentheses
#### WarningText
  Useless parentheses.

#### HelpText
  Useless parentheses should be removed.
  Example(s):

  ``` java
      
  public class Foo {

     private int _bar1;
     private Integer _bar2;

     public void setBar(int n) {
        _bar1 = Integer.valueOf((n)); // here
        _bar2 = (n); // and here
     }

  }
      
      
  ```

#### Tags
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor


## FH_WLMUB
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=While Loops Must Use Braces
#### WarningText
  Avoid using 'while' statements without curly braces.

#### HelpText
  Avoid using ‘while’ statements without using braces to surround the code block. If the code formatting or indentation is lost then it becomes difficult to separate the code being controlled from the rest.

  Example(s):

  ``` java
  while (true) // not recommended
    x++;
  while (true) { // preferred approach
    x++;
  }
  ```

#### Tags
- /collection/SEI CERT/EXP52-J
- /general/Code Style Rules
- /tool/SourceMeter/FaultHunter

#### Settings
- Priority=Minor



