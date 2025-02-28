# ToolDescription
## Default
### Description
  The RTEHunter module of SourceMeter can detect potential runtime errors in Java applications. These runtime errors are represented by the instances of Java class RuntimeException. The detection is based on an interprocedural symbolic execution engine.

### ID=RTEHunter

# TagMetadata
## general
### Best Practice Rules
##### Summarized=true
##### Description
  Rules which enforce generally accepted best practices.

### Clone
##### Description
  **Clone metrics:** measure the amount of copy-paste programming in the source code.

### Code Style Rules
##### Summarized=true
##### Description
  Rules which enforce a specific coding style.

### Cohesion
##### Description
  **Cohesion metrics:** measure to what extent the source code elements are coherent in the system.

### Complexity
##### Description
  **Complexity metrics:** measure the complexity of source code elements (typically algorithms).

### Coupling
##### Description
  **Coupling metrics:** measure the amount of interdependencies of source code elements.

### Design Rules
##### Summarized=true
##### Description
  Rules that help you discover design issues.

### Documentation
##### Description
  **Documentation metrics:** measure the amount of comments and documentation of source code elements in the system.

### Documentation Rules
##### Summarized=true
##### Description
  Rules that are related to code documentation.

### Error Prone Rules
##### Summarized=true
##### Description
  Rules to detect constructs that are either broken, extremely confusing or prone to runtime errors.

### Inheritance
##### Description
  **Inheritance metrics:** measure the different aspects of the inheritance hierarchy of the system.

### Performance Rules
##### Summarized=true
##### Description
  Rules that flag suboptimal code.

### Runtime Rules
##### Summarized=true
##### Description
  These rules deal with different runtime issues.

### Size
##### Description
  **Size metrics:** measure the basic properties of the analyzed system in terms of different cardinalities (e.g. number of code lines, number of classes or methods).

### Vulnerability Rules
##### Summarized=true
##### Description
  These rules deal with different security issues arise with tainting user inputs in web applications.

# Metrics
## RH_CCE
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=ClassCastException
#### WarningText
  %

#### HelpText
  Invalid casting which causes a ClassCastException.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package


## RH_DBZ
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Division By Zero
#### WarningText
  %

#### HelpText
  Division by zero causes an ArithmeticException.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package


## RH_IL
### Default
#### Enabled=false
#### Warning=true
#### DisplayName=Infinite Loop
#### WarningText
  %

#### HelpText
  Infinite loop.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package


## RH_IOB
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Index Out Of Bounds
#### WarningText
  %

#### HelpText
  Indexing an array by an index which is less than zero, or greater than its size.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package


## RH_NAS
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Negative Array Size
#### WarningText
  %

#### HelpText
  Creating an array with negative size.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package


## RH_NPE
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=NullPointerException
#### WarningText
  %

#### HelpText
  Null pointer dereferenced which causes a NullPointerException.

#### Tags
- /general/Runtime Rules
- /tool/SourceMeter/RTEHunter

#### Settings
- Priority=Blocker

### java -> Default
#### Enabled=false
#### Calculated
- Annotation
- Class
- Component
- Enum
- Interface
- Method
- Package



