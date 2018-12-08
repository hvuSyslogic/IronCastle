using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SignedData = org.bouncycastle.asn1.pkcs.SignedData;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using X509StreamParserSpi = org.bouncycastle.x509.X509StreamParserSpi;
	using StreamParsingException = org.bouncycastle.x509.util.StreamParsingException;

	public class X509CRLParser : X509StreamParserSpi
	{
		private static readonly PEMUtil PEM_PARSER = new PEMUtil("CRL");

		private ASN1Set sData = null;
		private int sDataObjectCount = 0;
		private InputStream currentStream = null;

		private CRL readDERCRL(InputStream @in)
		{
			ASN1InputStream dIn = new ASN1InputStream(@in);
			ASN1Sequence seq = (ASN1Sequence)dIn.readObject();

			if (seq.size() > 1 && seq.getObjectAt(0) is ASN1ObjectIdentifier)
			{
				if (seq.getObjectAt(0).Equals(PKCSObjectIdentifiers_Fields.signedData))
				{
					sData = (new SignedData(ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true))).getCRLs();

					return getCRL();
				}
			}

			return new X509CRLObject(CertificateList.getInstance(seq));
		}

		private CRL getCRL()
		{
			if (sData == null || sDataObjectCount >= sData.size())
			{
				return null;
			}

			return new X509CRLObject(CertificateList.getInstance(sData.getObjectAt(sDataObjectCount++)));
		}

		private CRL readPEMCRL(InputStream @in)
		{
			ASN1Sequence seq = PEM_PARSER.readPEMObject(@in);

			if (seq != null)
			{
				return new X509CRLObject(CertificateList.getInstance(seq));
			}

			return null;
		}

		public override void engineInit(InputStream @in)
		{
			currentStream = @in;
			sData = null;
			sDataObjectCount = 0;

			if (!currentStream.markSupported())
			{
				currentStream = new BufferedInputStream(currentStream);
			}
		}

		public override object engineRead()
		{
			try
			{
				if (sData != null)
				{
					if (sDataObjectCount != sData.size())
					{
						return getCRL();
					}
					else
					{
						sData = null;
						sDataObjectCount = 0;
						return null;
					}
				}

				currentStream.mark(10);
				int tag = currentStream.read();

				if (tag == -1)
				{
					return null;
				}

				if (tag != 0x30) // assume ascii PEM encoded.
				{
					currentStream.reset();
					return readPEMCRL(currentStream);
				}
				else
				{
					currentStream.reset();
					return readDERCRL(currentStream);
				}
			}
			catch (Exception e)
			{
				throw new StreamParsingException(e.ToString(), e);
			}
		}

		public override Collection engineReadAll()
		{
			CRL crl;
			List certs = new ArrayList();

			while ((crl = (CRL)engineRead()) != null)
			{
				certs.add(crl);
			}

			return certs;
		}
	}

}