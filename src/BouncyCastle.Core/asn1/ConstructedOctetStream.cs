using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	public class ConstructedOctetStream : InputStream
	{
		private readonly ASN1StreamParser _parser;

		private bool _first = true;
		private InputStream _currentStream;

		public ConstructedOctetStream(ASN1StreamParser parser)
		{
			_parser = parser;
		}

		public virtual int read(byte[] b, int off, int len)
		{
			if (_currentStream == null)
			{
				if (!_first)
				{
					return -1;
				}

				ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

				if (s == null)
				{
					return -1;
				}

				_first = false;
				_currentStream = s.getOctetStream();
			}

			int totalRead = 0;

			for (;;)
			{
				int numRead = _currentStream.read(b, off + totalRead, len - totalRead);

				if (numRead >= 0)
				{
					totalRead += numRead;

					if (totalRead == len)
					{
						return totalRead;
					}
				}
				else
				{
					ASN1OctetStringParser aos = (ASN1OctetStringParser)_parser.readObject();

					if (aos == null)
					{
						_currentStream = null;
						return totalRead < 1 ? -1 : totalRead;
					}

					_currentStream = aos.getOctetStream();
				}
			}
		}

		public virtual int read()
		{
			if (_currentStream == null)
			{
				if (!_first)
				{
					return -1;
				}

				ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

				if (s == null)
				{
					return -1;
				}

				_first = false;
				_currentStream = s.getOctetStream();
			}

			for (;;)
			{
				int b = _currentStream.read();

				if (b >= 0)
				{
					return b;
				}

				ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

				if (s == null)
				{
					_currentStream = null;
					return -1;
				}

				_currentStream = s.getOctetStream();
			}
		}
	}

}