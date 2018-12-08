using System;
using System.IO;

namespace org.bouncycastle.Port.java.io
{
    public class ByteArrayInputStream : InputStream
    {
        private readonly MemoryStream _stream;

        public ByteArrayInputStream(byte[] input)
        {
            _stream = new MemoryStream(input);
        }

        public ByteArrayInputStream(byte[] input, int inOff, int inLen)
        {
            throw new NotImplementedException();
        }

        public override int read()
        {
            return _stream.ReadByte();
        }

        public override long skip(long l)
        {
            if (l >= _stream.Length - _stream.Position)
                l = _stream.Length - _stream.Position;

            _stream.Seek(l, SeekOrigin.Current);

            return l;
        }

        public override int read(byte[] b)
        {
            return _stream.Read(b, 0, (int)_stream.Length);
        }

        public override int read(byte[] b, int offset, int length)
        {
            return _stream.Read(b, offset, length);
        }

        public override int available()
        {
            return (int)(_stream.Length - _stream.Position);
        }

        public override void close()
        {
            _stream.Dispose();
        }

        public override void mark(int readlimit)
        {
            throw new NotImplementedException();
        }

        public override void reset()
        {
            throw new NotImplementedException();
        }

        public override bool markSupported()
        {
            throw new NotImplementedException();
        }
    }
}
