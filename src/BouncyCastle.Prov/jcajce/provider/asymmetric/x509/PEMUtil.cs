using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class PEMUtil
	{
		private readonly string _header1;
		private readonly string _header2;
		private readonly string _header3;
		private readonly string _footer1;
		private readonly string _footer2;
		private readonly string _footer3;

		public PEMUtil(string type)
		{
			_header1 = "-----BEGIN " + type + "-----";
			_header2 = "-----BEGIN X509 " + type + "-----";
			_header3 = "-----BEGIN PKCS7-----";
			_footer1 = "-----END " + type + "-----";
			_footer2 = "-----END X509 " + type + "-----";
			_footer3 = "-----END PKCS7-----";
		}

		private string readLine(InputStream @in)
		{
			int c;
			StringBuffer l = new StringBuffer();

			do
			{
				while (((c = @in.read()) != '\r') && c != '\n' && (c >= 0))
				{
					l.append((char)c);
				}
			} while (c >= 0 && l.length() == 0);

			if (c < 0)
			{
				return null;
			}

			// make sure we parse to end of line.
			if (c == '\r')
			{
				// a '\n' may follow
				@in.mark(1);
				if (((c = @in.read()) == '\n'))
				{
					@in.mark(1);
				}

				if (c > 0)
				{
					@in.reset();
				}
			}

			return l.ToString();
		}

		public virtual ASN1Sequence readPEMObject(InputStream @in)
		{
			string line;
			StringBuffer pemBuf = new StringBuffer();

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(_header1, StringComparison.Ordinal) || line.StartsWith(_header2, StringComparison.Ordinal) || line.StartsWith(_header3, StringComparison.Ordinal))
				{
					break;
				}
			}

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(_footer1, StringComparison.Ordinal) || line.StartsWith(_footer2, StringComparison.Ordinal) || line.StartsWith(_footer3, StringComparison.Ordinal))
				{
					break;
				}

				pemBuf.append(line);
			}

			if (pemBuf.length() != 0)
			{
				try
				{
					return ASN1Sequence.getInstance(Base64.decode(pemBuf.ToString()));
				}
				catch (Exception)
				{
					throw new IOException("malformed PEM data encountered");
				}
			}

			return null;
		}
	}

}