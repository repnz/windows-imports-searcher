from __future__ import print_function
import pefile
import os
import json
import argparse
import fnmatch


TITLE = 'Windows Imports Searcher'
DESC =\
    """
    A tool to index and search for imports and exports in executables.
    This tool can create index files for indexed directories that contains executables.
    The tool lets you search for imports/exports inside these directories.
    Index files are basically JSON files, so you can open them and search yourself.
    """


def main():
    commands = [
        SearchCommand,
        IndexCommand,
        MergeCommand
    ]

    parser = argparse.ArgumentParser(
        prog=TITLE,
        description=DESC
    )

    subparsers = parser.add_subparsers(dest='command')

    for command in commands:
        command_parser = subparsers.add_parser(
            name=command.name,
            help=command.help
        )

        command.configure_args(command_parser)

    args = parser.parse_args()

    for command in commands:
        if command.name == args.command:
            try:
                command.validate_args(args)
                command.run(args)
            except CommandError as e:
                print(str(e))
            break


class BaseCommand(object):
    @classmethod
    def configure_args(cls, parser):
        raise NotImplemented

    @classmethod
    def run(cls, args):
        raise NotImplemented

    @classmethod
    def validate_args(cls, args):
        return True


class IndexCommand(BaseCommand):
    name = 'index'
    help = 'Index imports of executables in certain directories'

    @classmethod
    def configure_args(cls, parser):

        parser.add_argument('-i', '--input-dirs', nargs='+', required=True,
                                  help='List of directories to parse.')

        parser.add_argument('-o', '--output', required=True,
                                  help="Output index file to create")

    @classmethod
    def validate_args(cls, args):
        args.input_dirs = set(args.input_dirs)

        for input_dir in args.input_dirs:
            if not os.path.exists(input_dir):
                raise CommandError("Directory {} does not exist".format(input_dir))

        if os.path.exists(args.output):
            raise CommandError("Output file already exists")

    @classmethod
    def run(cls, args):
        index_obj = {}

        for input_dir in args.input_dirs:
            input_dir = os.path.abspath(input_dir)
            dir_obj = IndexCommand.get_directory_executables_metadata(input_dir)
            index_obj[input_dir] = dir_obj

        write_json(args.output, index_obj)

    @staticmethod
    def get_directory_executables_metadata(directory):
        executable_metadata = {}

        for file_name in os.listdir(directory):
            if not (file_name.endswith('.exe') or file_name.endswith('.dll') or file_name.endswith('.sys') or file_name.endswith('.ocx')):
                continue

            file_path = os.path.join(directory, file_name)
            print("Indexing", file_path)

            # noinspection PyBroadException
            try:
                executable_metadata[file_name] = IndexCommand.get_executable_metadata(file_path)
            except Exception as e:
                executable_metadata[file_name] = {'Error': str(e)}

        return executable_metadata

    @staticmethod
    def get_executable_metadata(file_path):
        pe = pefile.PE(file_path)

        return {
            'imports': IndexCommand.get_imports(pe),
            'exports': IndexCommand.get_exports(pe)
        }

    @staticmethod
    def get_imports(pe):
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {}

        imports = {}

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imported_functions = []

            for imp in entry.imports:
                if imp.name is None:
                    imported_functions.append(imp.ordinal)
                else:
                    imported_functions.append(imp.name.decode('ascii'))

            imports[entry.dll.decode('ascii')] = imported_functions

        return imports

    @staticmethod
    def get_exports(pe):
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        exports = []

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                exports.append(exp.ordinal)
            else:
                exports.append(exp.name.decode('ascii'))

        return exports


class SearchCommand(BaseCommand):
    name = 'search'
    help = 'Search for functions in an index file'

    @classmethod
    def configure_args(cls, parser):
        parser.add_argument('-i', '--input-indexes', nargs='+', required=True,
                            help='Index files to search in.')

        parser.add_argument(
            '-f', '--functions', required=True, nargs='+',
            help='Function expressions to search.' 
                 'Function expressions are similar to WinDbg.' 
                 '<dll_name>!<function_name>' 
                 'You can use wildcard on both sides'
        )

        parser.add_argument('-u', '--unique', default=False, action='store_true',
                            help='Flag that specifies if you want an executable'
                                 'to be printed only once if it fits one of the conditions.')

    @classmethod
    def validate_args(cls, args):
        for index_file in args.input_indexes:
            if not os.path.exists(index_file):
                raise CommandError("Index file {} does not exist".format(index_file))

    @classmethod
    def run(cls, args):
        merged_obj = MergeCommand.merge_files(args.input_indexes)

        for term in args.functions:
            for base_dir, files in merged_obj.iteritems():
                for file_name, file_metadata in files.iteritems():
                    file_path = os.path.join(base_dir, file_name)
                    try:
                        SearchCommand.search_file_metadata(args.unique, file_path, file_metadata, term)
                    except CommandError:
                        raise
                    except Exception as e:
                        raise Exception('ERROR PROCESSING: ', file_path, str(e))

    @staticmethod
    def search_file_metadata(unique, file_path, file_metadata, term):
        if '!' in term:
            module, func = term.split('!')
        else:
            module = '*'
            func = term

        if func == '*' and module == '*':
            raise CommandError("Invalid term: *!*")

        if func == '*':
            SearchCommand.search_modules(unique, file_path, file_metadata, module)
        else:
            found = SearchCommand.search_imports(unique, file_path, file_metadata, module, func)

            if found and unique:
                return

            SearchCommand.search_exports(unique, file_path, file_metadata, module, func)

    @staticmethod
    def search_imports(unique, file_path, file_metadata, module, func):
        imports = file_metadata.get('imports', {})

        found = False

        for module_name, imported_functions in imports.iteritems():
            if not fnmatch.fnmatch(module_name, module):
                continue

            for imported_func in imported_functions:
                if not isinstance(imported_func, unicode):
                    continue
                if fnmatch.fnmatch(imported_func, func):
                    found = True
                    print(file_path, 'Imports', module_name + '!' + imported_func)

                    if unique:
                        return True

        return found

    @staticmethod
    def search_exports(unique, file_path, file_metadata, module, func):
        if module != '*':
            return

        found = False
        exports = file_metadata.get('exports', [])

        for exported_function in exports:
            if not isinstance(exported_function, unicode):
                continue
            if fnmatch.fnmatch(exported_function, func):
                found = True
                print(file_path, 'Exports', exported_function)

                if unique:
                    return True
        return found

    @staticmethod
    def search_modules(unique, file_path, file_metadata, module):
        found = False
        imports = file_metadata.get('imports', {})

        for module_name in imports.iterkeys():
            if fnmatch.fnmatch(module_name, module):
                found = True
                print(file_path, 'Imports Module', module_name)

                if unique:
                    return True
        return found


class MergeCommand(BaseCommand):
    name = 'merge'
    help = 'Merge indexes of different index files'

    @classmethod
    def configure_args(cls, parser):
        parser.add_argument('-i', '--input-indexes', nargs='+', required=True,
                                  help='List of index files to merge')
        parser.add_argument('-o', '--output-file', required=True,
                                  help='Output index file to create')

    @classmethod
    def validate_args(cls, args):
        if os.path.exists(args.output_file):
            raise CommandError('Output file already exists.')

        args.input_indexes = set(args.input_indexes)

        if len(args.input_indexes) <= 1:
            raise CommandError('At least 2 input files has to be specified')

        for input_index_file_path in args.input_indexes:
            if not os.path.exists(input_index_file_path):
                raise CommandError("Input file '{}' does not exist".format(input_index_file_path))

    @classmethod
    def run(cls, args):
        merged_obj = MergeCommand.merge_files(args.input_indexes)
        write_json(args.output_file, merged_obj)

    @staticmethod
    def merge_files(files):
        merged_obj = {}

        for input_index in files:
            print('Reading file', input_index)
            obj = load_json(input_index)
            merged_obj.update(obj)

        return merged_obj


class CommandError(Exception):
    pass


def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def write_json(file_path, obj):
    with open(file_path, 'w') as f:
        json.dump(obj, f, indent=2)

if __name__ == '__main__':
    main()

