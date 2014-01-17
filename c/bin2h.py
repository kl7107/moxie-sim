# Convert any binary file to a C include file
import sys

data = open(sys.argv[1], 'rb').read()

print 'Read %s bytes of tarfile data' % len(data)

fd = open(sys.argv[2], 'wb')

fd.write('unsigned char moxie_binary_data[%s] = {\n' % len(data))

for val in data:
    fd.write('%s,\n' % ord(val))

fd.write('};\n')


