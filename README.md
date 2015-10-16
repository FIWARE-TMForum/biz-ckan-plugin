# WStore CKAN Plugin

Plugin to include CKAN datasets as a native resource in [WStore](https://github.com/conwetlab/WStore). This plugin 
validates that the provided datasets are valid and that the user that creates is the owner of the dataset. If the
provided link does not point to a valid CKAN dataset or the owner of the dataset is not the same than the one that
is creating the resource, the resource creation process will fail and an suitable message will be returned.

## Installation
To install the plugin, the first thing that you must do is to compress it in a ZIP file. To do so, you can run the
following command:

```
zip ckanplugin.zip ckan_dataset.py package.json
```

Then, go to the folder where WStore installed and run the following command in the `src` folder:

```
./manage.py loadplugin <PATH_TO_THE_ZIP_FILE>
```

**Note**: Replace `<PATH_TO_THE_ZIP_FILE>` by the path where the file generated in the previous step is located.
