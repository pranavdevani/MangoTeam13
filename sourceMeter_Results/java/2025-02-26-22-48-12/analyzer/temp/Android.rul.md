# ToolDescription
## Default
### Description
  AndroidHunter is the module of SourceMeter, which looks for Android specific coding rule violations. This module checks the Java sources of the Android projects for common Android specific faults and anti-patterns. AndroidHunter reimplements all the corresponding PMD rules and additionally it provides some checks that are not available in PMD. Such as the other modules of SourceMeter, AndroidHunter also works on the precise Abstract Semantic Graph which results in higher precision and recall compared to other tools with a rougher syntactic analysis.

### ID=AndroidHunter

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
## AH_CSF
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Call Super First
#### WarningText
  The super.%() is not the first method invocation in the override of %().

#### HelpText
  **Call Super First:** Super call should be the first method invocation in the override ofthe following methods of the Activity, Application, Service and Fragmentclasses:

  -   onCreate()
  -   onConfigurationChanged()
  -   onPostCreate()
  -   onPostResume()
  -   onRestart()
  -   onRestorInstanceState()
  -   onResume()
  -   onStart()

  Example(s):
  ``` java
      public class MyActivity extends Activity{
        public void onCreate(Bundle bundle) {
          foo();
          ...
          super.onCreate(bundle);
          ...
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Major

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


## AH_CSL
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Call Super Last
#### WarningText
  The super.%() is not the last method invocation in the override of %().

#### HelpText
  **Call Super Last:** Super call should be the last method invocation in the override ofthe following methods of the Activity, Application, Service and Fragment classes:

  -   finish()
  -   onDestroy()
  -   onPause()
  -   onSaveInstanceState()
  -   onStop()
  -   onTerminate()

  Example(s):
  ``` java
      public class MyActivity extends Activity{
        public void onStop() {
          ...
          super.onStop();
          ...
          foo();
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Major

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


## AH_DNHCSDC
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Do not hard code the SD card.
#### WarningText
  Do not hard code the SD card.

#### HelpText
  **Do Not Hard Code SD Card:** Hard-coding external storage directory can easily lead to faults, asit can differ on different devices. Instead of “/sdcard” use thegetExternalStorageDirectory() method of the android.os.Environment class.

  Example(s):
  ``` java
      public class MyActivity extends Activity{
        public void foo() {
          String storage =“/sdcard/myfolder”;
          ...
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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


## AH_DNODICP
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Do Not Open Database In ContentProvider
#### WarningText
  %() call in ContentProvider.onCreate().

#### HelpText
  **Do Not Open Database In ContentProvider:** Database upgrade may take a long time, you should not call thegetWritableDatabase() and the getReadableDatabase() methods from the ContentProvider.onCreate().

  Example(s):
  ``` java
      public class MyContentProvider extends ContentProvider{
        public boolean onCreate() {
          DatabaseHelper foo = newDatabaseHelper(getContext());
          SQLiteDatabase db = foo.getReadableDatabase();
          ...
        }
      }
  ```

#### Tags
- /general/Performance Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Minor

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


## AH_DNSBF
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Database Name Should Be Final
#### WarningText
  % contains the name of a database which could be final.

#### HelpText
  **Database Name Should Be Final:** The name of a database should be final, if it is possible.

  Example(s):
  ``` java
      public class DatabaseHelper extends SQLiteOpenHelper{
        private String DATABASE_NAME =“mydatabase.db”
        ...
        // The content of DATABASE_NAME doesnot change
        ...
        DatabaseHelper(Context context) {
          super(context,DATABASE_NAME, DATABASE_VERSION);
          ...
        }
      }
  ```

#### Tags
- /general/Design Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Minor

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


## AH_ISC
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Is Super Called
#### WarningText
  Missing super.%() call.

#### HelpText
  **Is Super Called:** In the classes, which inherits from Activity, you must call throughto the super class's implementation, if you override the so-called lifecycle methods.Otherwise, an exception will be thrown.The Activity’s lifecycle methodsare the following:

  -   onCreate()
  -   onStart()
  -   onPause()
  -   onResume()
  -   onDestroy()
  -   onRestart()
  -   onStop()
  -   onSaveInstanceState()

  Example(s):
  ``` java
      public class MyActivity extends Activity{
        @Override
        public void onCreate(BundlesavedInstanceState) {
          ...
          //Missing super.onCreate()
          ...
        }
        ...
        @Override
        protected void onStop() {
          ...
          //Missing super.onStop()
          ...
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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


## AH_ISCF
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Is Super Called Fragment
#### WarningText
  super.%() call is missing. Derived classes must call through to the super class's implementation of this method.

#### HelpText
  **Is Super Called Fragment:** In the classes, which extends Fragment, you must call through tothe super class's implementation, if you override the following methods:

  -   onInflate()
  -   onAttach()
  -   onCreate()
  -   onActivityCreated()
  -   onViewStateRestored()
  -   onStart()
  -   onResume()
  -   onConfigurationChanged ()
  -   onPause()
  -   onStop()
  -   onLowMemory()
  -   onTrimMemory()
  -   onDestroyView()
  -   onDestroy()
  -   onDetach()

  Otherwise, an exception will be thrown.

  Example(s):
  ``` java
      public class MyFragment extends Fragment{
        @Override
        public void onAttach(Activity activity){
          ...
          //Missing super.onAttach(activity)
          ...
        }
        ...
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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


## AH_MRU
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Missing Remove Updates
#### WarningText
  Missing removeUpdates() call for %.

#### HelpText
  **Missing Remove Updates:** If you attach a listener to a location resource then you shouldalways detach it.

  Example(s):
  ``` java
      public class MyActivity extends Activity implementsLocationListener {
        @Override
        public void onStart(BundlesavedInstanceState) {
          ...
          myLocationManager.requestLocationUpdates(
            LocationManager.GPS_PROVIDER,0, 0, this);
          ...
        }
        ...
        //Missing lm.removeUpdates(this);
        ...
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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


## AH_MURIA
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Missing Unregister Receiver In Activity
#### WarningText
  Missing unregister % in the %.onPause().

#### HelpText
  **Missing Unregister Receiver In Activity:** If you register a receiver in your Activity.onResume()implementation, you should unregister it in Activity.onPause() You won'treceive intents when paused, and this will cut down on unnecessary systemoverhead.

  Example(s):
  ``` java
      public class MyActivity extends Activity {
        @Override
        public void onResume() {
          ...
          registerReceiver(myReceiver,new IntentFilter(
           WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
          ...
        }
        ...
        @Override
        public void onPause() {
          ...
          //Missing unregisterReceiver(myReceiver);
          ...
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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


## AH_RRITWP
### Default
#### Enabled=true
#### Warning=true
#### DisplayName=Resource Release In The Wrong Place
#### WarningText
  % call in the implementation of onSaveInstaceState().

#### HelpText
  **Resource Release In The Wrong Place:** Do not place any release of resources inActivity.onSaveInstanceState(), because this callback is not always called whenan activity is being placed in the background or on its way to destruction. Anideal place to release resources is the Activity.onPause().

  Example(s):
  ``` java
      public class MyActivity extends Activity {
        @Override
        public void onSaveInstanceState(BundeloutState) {
          ...
         unregisterReceiver(myReceiver); //wrong place
          ...
        }
        ...
        public void onPause() {
          ...
          unregisterReceiver(myReceiver);//good place
          ...
        }
      }
  ```

#### Tags
- /general/Error Prone Rules
- /tool/SourceMeter/AndroidHunter

#### Settings
- Priority=Critical

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



