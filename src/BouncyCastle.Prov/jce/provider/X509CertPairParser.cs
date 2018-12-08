using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using CertificatePair = org.bouncycastle.asn1.x509.CertificatePair;
	using X509CertificatePair = org.bouncycastle.x509.X509CertificatePair;
	using X509StreamParserSpi = org.bouncycastle.x509.X509StreamParserSpi;
	using StreamParsingException = org.bouncycastle.x509.util.StreamParsingException;

	public class X509CertPairParser : X509StreamParserSpi
	{
		private InputStream currentStream = null;

		private X509CertificatePair readDERCrossCertificatePair(InputStream @in)
		{
			ASN1InputStream dIn = new ASN1InputStream(@in);
			ASN1Sequence seq = (ASN1Sequence)dIn.readObject();
			CertificatePair pair = CertificatePair.getInstance(seq);
			return new X509CertificatePair(pair);
		}

		public override void engineInit(InputStream @in)
		{
			currentStream = @in;

			if (!currentStream.markSupported())
			{
				currentStream = new BufferedInputStream(currentStream);
			}
		}

		public override object engineRead()
		{
			try
			{

				currentStream.mark(10);
				int tag = currentStream.read();

				if (tag == -1)
				{
					return null;
				}

				currentStream.reset();
				return readDERCrossCertificatePair(currentStream);
			}
			catch (Exception e)
			{
				throw new StreamParsingException(e.ToString(), e);
			}
		}

		public override Collection engineReadAll()
		{
			X509CertificatePair pair;
			List certs = new ArrayList();

			while ((pair = (X509CertificatePair)engineRead()) != null)
			{
				certs.add(pair);
			}

			return certs;
		}
	}

}