

from framework.file_filter import FileFilter


f = FileFilter()

f.include_fnmatches(['*.cpp'])
f.exclude_fnmatches(['src/*/init.cpp'])

print(f.evaluate("src/wax/init.cpp"))
print(f.evaluate("src/main.cpp"))
print(f.evaluate("src/main.h"))
