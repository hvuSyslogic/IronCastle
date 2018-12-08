using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SignedData = org.bouncycastle.asn1.pkcs.SignedData;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// class for dealing with X509 certificates.
	/// <para>
	/// At the moment this will deal with "-----BEGIN CERTIFICATE-----" to "-----END CERTIFICATE-----"
	/// base 64 encoded certs, as well as the BER binaries of certificates and some classes of PKCS#7
	/// objects.
	/// </para>
	/// </summary>
	public class CertificateFactory : CertificateFactorySpi
	{
		private readonly JcaJceHelper bcHelper = new BCJcaJceHelper();

		private static readonly PEMUtil PEM_CERT_PARSER = new PEMUtil("CERTIFICATE");
		private static readonly PEMUtil PEM_CRL_PARSER = new PEMUtil("CRL");
		private static readonly PEMUtil PEM_PKCS7_PARSER = new PEMUtil("PKCS7");

		private ASN1Set sData = null;
		private int sDataObjectCount = 0;
		private InputStream currentStream = null;

		private ASN1Set sCrlData = null;
		private int sCrlDataObjectCount = 0;
		private InputStream currentCrlStream = null;

		private java.security.cert.Certificate readDERCertificate(ASN1InputStream dIn)
		{
			return getCertificate(ASN1Sequence.getInstance(dIn.readObject()));
		}

		private java.security.cert.Certificate readPEMCertificate(InputStream @in)
		{
			return getCertificate(PEM_CERT_PARSER.readPEMObject(@in));
		}

		private java.security.cert.Certificate getCertificate(ASN1Sequence seq)
		{
			if (seq == null)
			{
				return null;
			}

			if (seq.size() > 1 && seq.getObjectAt(0) is ASN1ObjectIdentifier)
			{
				if (seq.getObjectAt(0).Equals(PKCSObjectIdentifiers_Fields.signedData))
				{
					sData = SignedData.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true)).getCertificates();

					return getCertificate();
				}
			}

			return new X509CertificateObject(bcHelper, Certificate.getInstance(seq));
		}

		private java.security.cert.Certificate getCertificate()
		{
			if (sData != null)
			{
				while (sDataObjectCount < sData.size())
				{
					object obj = sData.getObjectAt(sDataObjectCount++);

					if (obj is ASN1Sequence)
					{
					   return new X509CertificateObject(bcHelper, Certificate.getInstance(obj));
					}
				}
			}

			return null;
		}


		public virtual CRL createCRL(CertificateList c)
		{
			return new X509CRLObject(bcHelper, c);
		}

		private CRL readPEMCRL(InputStream @in)
		{
			return getCRL(PEM_CRL_PARSER.readPEMObject(@in));
		}

		private CRL readDERCRL(ASN1InputStream aIn)
		{
			return getCRL(ASN1Sequence.getInstance(aIn.readObject()));
		}

		private CRL getCRL(ASN1Sequence seq)
		{
			if (seq == null)
			{
				return null;
			}

			if (seq.size() > 1 && seq.getObjectAt(0) is ASN1ObjectIdentifier)
			{
				if (seq.getObjectAt(0).Equals(PKCSObjectIdentifiers_Fields.signedData))
				{
					sCrlData = SignedData.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true)).getCRLs();

					return getCRL();
				}
			}

			return createCRL(CertificateList.getInstance(seq));
		}

		private CRL getCRL()
		{
			if (sCrlData == null || sCrlDataObjectCount >= sCrlData.size())
			{
				return null;
			}

			return createCRL(CertificateList.getInstance(sCrlData.getObjectAt(sCrlDataObjectCount++)));
		}

		/// <summary>
		/// Generates a certificate object and initializes it with the data
		/// read from the input stream inStream.
		/// </summary>
		public virtual java.security.cert.Certificate engineGenerateCertificate(InputStream @in)
		{
			if (currentStream == null)
			{
				currentStream = @in;
				sData = null;
				sDataObjectCount = 0;
			}
			else if (currentStream != @in) // reset if input stream has changed
			{
				currentStream = @in;
				sData = null;
				sDataObjectCount = 0;
			}

			try
			{
				if (sData != null)
				{
					if (sDataObjectCount != sData.size())
					{
						return getCertificate();
					}
					else
					{
						sData = null;
						sDataObjectCount = 0;
						return null;
					}
				}

				InputStream pis;

				if (@in.markSupported())
				{
					pis = @in;
				}
				else
				{
					pis = new ByteArrayInputStream(Streams.readAll(@in));
				}

				pis.mark(1);
				int tag = pis.read();

				if (tag == -1)
				{
					return null;
				}

				pis.reset();
				if (tag != 0x30) // assume ascii PEM encoded.
				{
					return readPEMCertificate(pis);
				}
				else
				{
					return readDERCertificate(new ASN1InputStream(pis));
				}
			}
			catch (Exception e)
			{
				throw new ExCertificateException(this, "parsing issue: " + e.Message, e);
			}
		}

		/// <summary>
		/// Returns a (possibly empty) collection view of the certificates
		/// read from the given input stream inStream.
		/// </summary>
		public virtual Collection engineGenerateCertificates(InputStream inStream)
		{
			java.security.cert.Certificate cert;
			BufferedInputStream @in = new BufferedInputStream(inStream);

			List certs = new ArrayList();

			while ((cert = engineGenerateCertificate(@in)) != null)
			{
				certs.add(cert);
			}

			return certs;
		}

		/// <summary>
		/// Generates a certificate revocation list (CRL) object and initializes
		/// it with the data read from the input stream inStream.
		/// </summary>
		public virtual CRL engineGenerateCRL(InputStream @in)
		{
			if (currentCrlStream == null)
			{
				currentCrlStream = @in;
				sCrlData = null;
				sCrlDataObjectCount = 0;
			}
			else if (currentCrlStream != @in) // reset if input stream has changed
			{
				currentCrlStream = @in;
				sCrlData = null;
				sCrlDataObjectCount = 0;
			}

			try
			{
				if (sCrlData != null)
				{
					if (sCrlDataObjectCount != sCrlData.size())
					{
						return getCRL();
					}
					else
					{
						sCrlData = null;
						sCrlDataObjectCount = 0;
						return null;
					}
				}

				InputStream pis;

				if (@in.markSupported())
				{
					pis = @in;
				}
				else
				{
					pis = new ByteArrayInputStream(Streams.readAll(@in));
				}

				pis.mark(1);
				int tag = pis.read();

				if (tag == -1)
				{
					return null;
				}

				pis.reset();
				if (tag != 0x30) // assume ascii PEM encoded.
				{
					return readPEMCRL(pis);
				}
				else
				{ // lazy evaluate to help processing of large CRLs
					return readDERCRL(new ASN1InputStream(pis, true));
				}
			}
			catch (CRLException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new CRLException(e.ToString());
			}
		}

		/// <summary>
		/// Returns a (possibly empty) collection view of the CRLs read from
		/// the given input stream inStream.
		/// 
		/// The inStream may contain a sequence of DER-encoded CRLs, or
		/// a PKCS#7 CRL set.  This is a PKCS#7 SignedData object, with the
		/// only signficant field being crls.  In particular the signature
		/// and the contents are ignored.
		/// </summary>
		public virtual Collection engineGenerateCRLs(InputStream inStream)
		{
			CRL crl;
			List crls = new ArrayList();
			BufferedInputStream @in = new BufferedInputStream(inStream);

			while ((crl = engineGenerateCRL(@in)) != null)
			{
				crls.add(crl);
			}

			return crls;
		}

		public virtual Iterator engineGetCertPathEncodings()
		{
			return PKIXCertPath.certPathEncodings.iterator();
		}

		public virtual CertPath engineGenerateCertPath(InputStream inStream)
		{
			return engineGenerateCertPath(inStream, "PkiPath");
		}

		public virtual CertPath engineGenerateCertPath(InputStream inStream, string encoding)
		{
			return new PKIXCertPath(inStream, encoding);
		}

		public virtual CertPath engineGenerateCertPath(List certificates)
		{
			Iterator iter = certificates.iterator();
			object obj;
			while (iter.hasNext())
			{
				obj = iter.next();
				if (obj != null)
				{
					if (!(obj is X509Certificate))
					{
						throw new CertificateException("list contains non X509Certificate object while creating CertPath\n" + obj.ToString());
					}
				}
			}
			return new PKIXCertPath(certificates);
		}

		public class ExCertificateException : CertificateException
		{
			private readonly CertificateFactory outerInstance;

			internal Exception cause;

			public ExCertificateException(CertificateFactory outerInstance, Exception cause)
			{
				this.outerInstance = outerInstance;
				this.cause = cause;
			}

			public ExCertificateException(CertificateFactory outerInstance, string msg, Exception cause) : base(msg)
			{
				this.outerInstance = outerInstance;

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}