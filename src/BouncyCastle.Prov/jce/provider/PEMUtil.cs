using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class PEMUtil
	{
		private readonly string _header1;
		private readonly string _header2;
		private readonly string _footer1;
		private readonly string _footer2;

		public PEMUtil(string type)
		{
			_header1 = "-----BEGIN " + type + "-----";
			_header2 = "-----BEGIN X509 " + type + "-----";
			_footer1 = "-----END " + type + "-----";
			_footer2 = "-----END X509 " + type + "-----";
		}

		private string readLine(InputStream @in)
		{
			int c;
			StringBuffer l = new StringBuffer();

			do
			{
				while (((c = @in.read()) != '\r') && c != '\n' && (c >= 0))
				{
					if (c == '\r')
					{
						continue;
					}

					l.append((char)c);
				}
			} while (c >= 0 && l.length() == 0);

			if (c < 0)
			{
				return null;
			}

			return l.ToString();
		}

		public virtual ASN1Sequence readPEMObject(InputStream @in)
		{
			string line;
			StringBuffer pemBuf = new StringBuffer();

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(_header1, StringComparison.Ordinal) || line.StartsWith(_header2, StringComparison.Ordinal))
				{
					break;
				}
			}

			while (!string.ReferenceEquals((line = readLine(@in)), null))
			{
				if (line.StartsWith(_footer1, StringComparison.Ordinal) || line.StartsWith(_footer2, StringComparison.Ordinal))
				{
					break;
				}

				pemBuf.append(line);
			}

			if (pemBuf.length() != 0)
			{
				ASN1Primitive o = (new ASN1InputStream(Base64.decode(pemBuf.ToString()))).readObject();
				if (!(o is ASN1Sequence))
				{
					throw new IOException("malformed PEM data encountered");
				}

				return (ASN1Sequence)o;
			}

			return null;
		}
	}

}