# coding: utf-8
# csvcryptohashinglogic.py
# Copyright 2018 iTtelligent, LLC., Kirby J. Davis (kdavis@itelligentllc.com)

"""This file is part of iTelliHashCSV.

    iTelliHashCSV - A Cryptographic Hashing Application for CSV Files
    Copyright (C) 2018 iTelligent, LLC (Kirby J. Davis)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    """

import gc
import os.path
import sys

import pandas as pd
import sqlalchemy as sa
from Crypto.Hash import RIPEMD, SHA224, SHA256, SHA384, SHA512


class StringFolder(object):
    """
    Class that will fold strings. See 'fold_string'.
    This object may be safely deleted or go out of scope when
    strings have been folded.
    """

    def __init__(self):
        self.unicode_map = {}

    def fold_string(self, s):
        """
        Given a string (or unicode) parameter s, return a string object
        that has the same value as s (and may be s). For all objects
        with a given value, the same object will be returned. For unicode
        objects that can be coerced to a string with the same value, a
        string object will be returned.
        If s is not a string or unicode object, it is returned unchanged.
        :param s: a string or unicode object.
        :return: a string or unicode object.
        """
        # If s is not a string or unicode object, return it unchanged
        if not isinstance(s, str):
            return s

        # If s is already a string, then str() has no effect.
        # If s is Unicode, try and encode as a string and use intern.
        # If s is Unicode and can't be encoded as a string, this try
        # will raise a UnicodeEncodeError.
        try:
            return sys.intern(str(s))
        except UnicodeEncodeError:
            # Fall through and handle s as Unicode
            pass

        # Look up the unicode value in the map and return
        # the object from the map. If there is no matching entry,
        # store this unicode object in the map and return it.
        t = self.unicode_map.get(s, None)
        if t is None:
            # Put s in the map
            t = self.unicode_map[s] = s
        return t


def string_folding_wrapper(results):
    """
    This generator yields rows from the results as tuples,
    with all string values folded.
    """
    # Get the list of keys so that we build tuples with all
    # the values in key order.
    keys = list(results.keys())
    folder = StringFolder()
    for row in results:
        yield tuple(
            folder.fold_string(row[key])
            for key in keys
        )


class CSVCryptoHash(object):
    """
    Logic for hashing selected fields/columns selected by the user from CSV input file(s) selected by the
    user.

    """

    def __init__(self):
        self.hstr = 'sha512'
        self.h = SHA512.new()
        self.files2process = []
        self.fields2encrypt = []
        self.fields2process = []
        self.quotechar = '"'

        # CSV files separator. Default is a comma. Whitespace is ' ' or '\t' (tab)
        self.inputdelimiter = ','
        self.outputdelimiter = ','
        # The following should be set to True if the inputdelimiter is whitespace, False if anything else.
        self.delim_whitespace = False

        self.maxlen = 0
        self.inputdirectory = ''
        self.outputdirectory = ''

    def initialize_sqlite(self):
        self.SQLiteconnection = sa.create_engine('sqlite:///source.db')

    @staticmethod
    def remove_sqlite():
        os.remove('source.db')
        gc.collect()

    def identify_hash(self, hash2use):
        """ Identify type of cryptographic hashing to use for processing.

        :param hash2use: Value indicating type of hashing desired based upon user's input
        :return: No explicit value returned. Variables set for further processing.

        """
        if hash2use == 1:
            self.h = RIPEMD.new()
            self.hstr = 'ripemd160'
        elif hash2use == 2:
            self.h = SHA224.new()
            self.hstr = 'sha224'
        elif hash2use == 3:
            self.h = SHA256.new()
            self.hstr = 'sha256'
        elif hash2use == 4:
            self.h = SHA384.new()
            self.hstr = 'sha384'
        elif hash2use == 5:
            self.h = SHA512.new()
            self.hstr = 'sha512'

    def hash_text(self, desired_column):
        """ Hash individual fields/columns.

        :param desired_column: Field/column in CSV file to be processed
        :return: self.hashed_value: Hashed value of field/column processed

        """
        h = self.h.new()
        self.hashvalue = h.update(str.encode(str(desired_column)))
        self.hashed_value = h.hexdigest()
        return self.hashed_value

    def create_temp_db(self, files2process, fields2hash, inputdirectory):
        """ Processing logic for hashing the files and fields/columns selected by the
            user for processing. Input CSV files selected are iteratively looped through as well as the fields/columns
            that were selected. This function creates an SQLite database that is used during the processing
            to store data, perform in-placed sorting and de-duplication, etc.

        :param inputdirectory: Location of CSV input file(s)
        :param files2process: List containing the input CSV files selected for processing.
        :param fields2hash: List containing the fields/columns selected for processing.
        :return: Temporary SQLite database used for subsequent processing.
        """
        for self.file in files2process:

            # Read first line of selected file to get fieldnames available in this file
            if not self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delimiter=self.inputdelimiter, nrows=1)
            elif self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delim_whitespace=self.delim_whitespace,
                                                   nrows=1)

            # Identify fields to read and processed in the selected file based on user selections and fields available.
            self.fields2process = list(set(fields2hash).intersection(list(self.fieldsavailable)))

            if not self.delim_whitespace:
                self.pdcomposite = pd.read_csv(inputdirectory + self.file, usecols=self.fields2process, dtype=object,
                                               quotechar=self.quotechar, delimiter=self.inputdelimiter)
            elif self.delim_whitespace:
                self.pdcomposite = pd.read_csv(inputdirectory + self.file, usecols=self.fields2process, dtype=object,
                                               quotechar=self.quotechar, delim_whitespace=self.delim_whitespace)

            # Loop through selected fields, hash, and store them
            for self.field in self.fields2process:
                # Create "composite_mapfile".
                self.compositefile = self.pdcomposite.loc[:, [self.field]]
                self.compositefile.drop_duplicates(inplace=True)
                self.compositefile["Hashvalue"] = self.compositefile.apply(lambda c: self.hash_text(c.loc[self.field]),
                                                                           axis=1)
                self.compositefile["Plaintext"] = self.compositefile[self.field]
                self.compositefile["FieldName"] = self.field
                self.compositefile.drop([self.field], inplace=True, axis=1)
                self.compositefile.to_sql('data', self.SQLiteconnection, index=False, if_exists="append")

    def create_summary_hash_mapfile(self, fileextension, outputdirectory):
        """ Processing logic for hashing the file and fields/columns selected by the
            user for processing. This function creates a composite/summary 'mapfile' for all fields/columns
            selected for hashing within all input files chosen for processing.

        :param outputdirectory: Location for output files
        :param fileextension: File extension of input file.
        :return: Single CSV 'mapfile' for each input file(s) with the following characteristics:
                 Column Names: Hashvalue, Plaintext, FieldName
                 File Name: Hash_MapFile_<hash format chosen>.<fileextension>
        """

        # Read data from SQLite DB into pandas dataframe
        with self.SQLiteconnection.connect() as connection:
            results = connection.execution_options(stream_results=True).execute(
                'SELECT * FROM data ORDER By FieldName, Plaintext')
            df = pd.DataFrame(string_folding_wrapper(results))
            df = df.rename(columns={0: 'Hashvalue', 1: 'Plaintext', 2: 'FieldName'})

        # Remove any duplicates from CompositeMap
        df.drop_duplicates(inplace=True)

        # Write the de-duplicated CompositeMap to csv output file
        df.to_csv(outputdirectory + 'Hash_MapFile_' + self.hstr + fileextension, index=False,
                  encoding='utf-8', sep=self.outputdelimiter)

    def create_column_hash_mapfile(self, files2process, fields2hash, fileextension, inputdirectory, outputdirectory):
        """ Processing logic for hashing the file(s) and field(s) selected by the user for processing.
            This function creates a separate 'mapfile' for each field selected for hashing within all
            input files chosen for processing.

        :param outputdirectory: Location for output files
        :param inputdirectory: Location of CSV input file(s)
        :param fields2hash: Field(s) selected to be hashed.
        :param files2process: Current input file(s) being processed.
        :param fileextension: File extension of input file.
        :return: Separate CSV 'mapfile' for each hashed field/column written to same folder as input files with the
                 following characteristics:
                 Column Names: <Field Name>,<Field Name_Plaintext>.
                 File Name: <Field Name>_MapFile_<hash format chosen>.<fileextension>
        """
        for self.file in files2process:

            # Read first line of selected file to get fieldnames available in this file
            if not self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delimiter=self.inputdelimiter, nrows=1)
            elif self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delim_whitespace=self.delim_whitespace, nrows=1)

            # Identify fields to read and process in the selected file based on user selections and fields available.
            self.fields2process = list(set(fields2hash).intersection(list(self.fieldsavailable)))

            for field in self.fields2process:
                with self.SQLiteconnection.connect() as connection:
                    stmt = sa.text("SELECT * FROM data where FieldName == :fieldname ORDER BY Hashvalue")
                    results = connection.execution_options(stream_results=True).execute(stmt, fieldname=field)
                    df = pd.DataFrame(string_folding_wrapper(results))
                    df = df.rename(columns={0: 'Hashvalue', 1: 'Plaintext', 2: 'FieldName'})
                    df.drop('FieldName', axis=1, inplace=True)
                    newname = field + '_Plaintext'
                    df.columns = [field, newname]
                    df.drop_duplicates(inplace=True)
                    df.to_csv(outputdirectory + field + '_MapFile_' + self.hstr + fileextension, index=False,
                              encoding='utf-8', sep=self.outputdelimiter)

    def create_hashed_version_of_input(self, files2process, fields2hash, fileextension, inputdirectory,
                                       outputdirectory):
        """ Processing logic for hashing the file(s) and field(s) selected by the user for processing.
            This function creates a hashed version of the input file(s) chosen for processing.

        :param outputdirectory: Location for output files
        :param inputdirectory: Location of CSV input file(s)
        :param fileextension: File extension of input files.
        :param files2process: Current input file(s) being processed.
        :param fields2hash: Current field(s) being processed.
        :return: Hashed version of CSV input file(s) with the following characteristics:
                 Column Names: Original input file field names. Fields chosen for processing with have hashed values
                 while those fields not chosen for processing will have their original plaintext values.
                 File Name: Hashed_<Original input CSV file name>_<hash format chosen>.<fileextension>
        """

        self.mapfile = pd.read_sql_query("SELECT Plaintext, Hashvalue FROM data;", self.SQLiteconnection)
        self.mapping = self.mapfile[['Plaintext', 'Hashvalue']].set_index('Plaintext')['Hashvalue'].to_dict()

        for self.file in files2process:
            # Read first line of selected file to get fieldnames available in this file
            if not self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delimiter=self.inputdelimiter, nrows=1)
            elif self.delim_whitespace:
                self.fieldsavailable = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                                   delim_whitespace=self.delim_whitespace, nrows=1)

            # Identify fields to read and process in the selected file based on user selections and fields available.
            self.fields2process = list(set(fields2hash).intersection(list(self.fieldsavailable)))

            if not self.delim_whitespace:
                self.inputfile = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                             delimiter=self.inputdelimiter)
            elif self.delim_whitespace:
                self.inputfile = pd.read_csv(inputdirectory + self.file, dtype=object, quotechar=self.quotechar,
                                             delim_whitespace=self.delim_whitespace)
            self.inputfile[self.fields2process] = self.inputfile[self.fields2process].applymap(self.mapping.get)
            self.newname = 'Hashed_' + self.file.replace(fileextension, '_' + self.hstr + fileextension)
            self.inputfile.to_csv(outputdirectory + self.newname, index=False, encoding='utf-8',
                                  sep=self.outputdelimiter)
