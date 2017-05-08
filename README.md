# Business API Ecosystem CKAN Plugin

Plugin to include CKAN datasets as a native resource in the
[BAE](https://github.com/FIWARE-TMForum/Business-API-Ecosystem).
This plugin validates the provided dataset and checks whether the user 
that creates the product is its owner in CKAN. If the provided
link does not point to a valid CKAN dataset or the owner of the dataset
is not the same as the one that is creating the product, the product
creation process will fail and an suitable message will be returned.

## Requirements

In order to use this BAE plugin, the CKAN instance whose datasets are
offered must have installed the [private datasets CKAN extension](https://github.com/conwetlab/ckanext-privatedatasets)
which is used in order to grant access rights to customers.

## Installation

To install the plugin, the first thing that you must do is to compress
it in a ZIP file. To do so, you can run the following command:

```
zip ckanplugin.zip ckan_dataset.py package.json
```

Then, go the `src` directory included in the folder used to install the
Charging Backend component of the BAE, and run the following command:

```
./manage.py loadplugin <PATH_TO_THE_ZIP_FILE>
```

**Note**: Replace `<PATH_TO_THE_ZIP_FILE>` by the path where the file
generated in the previous step is located.
