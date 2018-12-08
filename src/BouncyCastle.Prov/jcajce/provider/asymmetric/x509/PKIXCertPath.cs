using org.bouncycastle.asn1;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using ContentInfo = org.bouncycastle.asn1.pkcs.ContentInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SignedData = org.bouncycastle.asn1.pkcs.SignedData;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using PemObject = org.bouncycastle.util.io.pem.PemObject;
	using PemWriter = org.bouncycastle.util.io.pem.PemWriter;

	/// <summary>
	/// CertPath implementation for X.509 certificates.
	/// </summary>
	public class PKIXCertPath : CertPath
	{
		private readonly JcaJceHelper helper = new BCJcaJceHelper();

		internal static readonly List certPathEncodings;

		static PKIXCertPath()
		{
			List encodings = new ArrayList();
			encodings.add("PkiPath");
			encodings.add("PEM");
			encodings.add("PKCS7");
			certPathEncodings = Collections.unmodifiableList(encodings);
		}

		private List certificates;

		/// <param name="certs"> </param>
		private List sortCerts(List certs)
		{
			if (certs.size() < 2)
			{
				return certs;
			}

			X500Principal issuer = ((X509Certificate)certs.get(0)).getIssuerX500Principal();
			bool okay = true;

			for (int i = 1; i != certs.size(); i++)
			{
				X509Certificate cert = (X509Certificate)certs.get(i);

				if (issuer.Equals(cert.getSubjectX500Principal()))
				{
					issuer = ((X509Certificate)certs.get(i)).getIssuerX500Principal();
				}
				else
				{
					okay = false;
					break;
				}
			}

			if (okay)
			{
				return certs;
			}

			// find end-entity cert
			List retList = new ArrayList(certs.size());
			List orig = new ArrayList(certs);

			for (int i = 0; i < certs.size(); i++)
			{
				X509Certificate cert = (X509Certificate)certs.get(i);
				bool found = false;

				X500Principal subject = cert.getSubjectX500Principal();

				for (int j = 0; j != certs.size(); j++)
				{
					X509Certificate c = (X509Certificate)certs.get(j);
					if (c.getIssuerX500Principal().Equals(subject))
					{
						found = true;
						break;
					}
				}

				if (!found)
				{
					retList.add(cert);
					certs.remove(i);
				}
			}

			// can only have one end entity cert - something's wrong, give up.
			if (retList.size() > 1)
			{
				return orig;
			}

			for (int i = 0; i != retList.size(); i++)
			{
				issuer = ((X509Certificate)retList.get(i)).getIssuerX500Principal();

				for (int j = 0; j < certs.size(); j++)
				{
					X509Certificate c = (X509Certificate)certs.get(j);
					if (issuer.Equals(c.getSubjectX500Principal()))
					{
						retList.add(c);
						certs.remove(j);
						break;
					}
				}
			}

			// make sure all certificates are accounted for.
			if (certs.size() > 0)
			{
				return orig;
			}

			return retList;
		}

		public PKIXCertPath(List certificates) : base("X.509")
		{
			this.certificates = sortCerts(new ArrayList(certificates));
		}

		/// <summary>
		/// Creates a CertPath of the specified type.
		/// This constructor is protected because most users should use
		/// a CertificateFactory to create CertPaths.
		/// 
		/// </summary>
		public PKIXCertPath(InputStream inStream, string encoding) : base("X.509")
		{
			try
			{
				if (encoding.Equals("PkiPath", StringComparison.OrdinalIgnoreCase))
				{
					ASN1InputStream derInStream = new ASN1InputStream(inStream);
					ASN1Primitive derObject = derInStream.readObject();
					if (!(derObject is ASN1Sequence))
					{
						throw new CertificateException("input stream does not contain a ASN1 SEQUENCE while reading PkiPath encoded data to load CertPath");
					}
					Enumeration e = ((ASN1Sequence)derObject).getObjects();
					certificates = new ArrayList();
					CertificateFactory certFactory = helper.createCertificateFactory("X.509");
					while (e.hasMoreElements())
					{
						ASN1Encodable element = (ASN1Encodable)e.nextElement();
						byte[] encoded = element.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
						certificates.add(0, certFactory.generateCertificate(new ByteArrayInputStream(encoded)));
					}
				}
				else if (encoding.Equals("PKCS7", StringComparison.OrdinalIgnoreCase) || encoding.Equals("PEM", StringComparison.OrdinalIgnoreCase))
				{
					inStream = new BufferedInputStream(inStream);
					certificates = new ArrayList();
					CertificateFactory certFactory = helper.createCertificateFactory("X.509");
					Certificate cert;
					while ((cert = certFactory.generateCertificate(inStream)) != null)
					{
						certificates.add(cert);
					}
				}
				else
				{
					throw new CertificateException("unsupported encoding: " + encoding);
				}
			}
			catch (IOException ex)
			{
				throw new CertificateException("IOException throw while decoding CertPath:\n" + ex.ToString());
			}
			catch (NoSuchProviderException ex)
			{
				throw new CertificateException("BouncyCastle provider not found while trying to get a CertificateFactory:\n" + ex.ToString());
			}

			this.certificates = sortCerts(certificates);
		}

		/// <summary>
		/// Returns an iteration of the encodings supported by this
		/// certification path, with the default encoding
		/// first. Attempts to modify the returned Iterator via its
		/// remove method result in an UnsupportedOperationException.
		/// </summary>
		/// <returns> an Iterator over the names of the supported encodings (as Strings)
		///  </returns>
		public virtual Iterator getEncodings()
		{
			return certPathEncodings.iterator();
		}

		/// <summary>
		/// Returns the encoded form of this certification path, using
		/// the default encoding.
		/// </summary>
		/// <returns> the encoded bytes </returns>
		/// <exception cref="java.security.cert.CertificateEncodingException"> if an encoding error occurs
		///  </exception>
		public virtual byte[] getEncoded()
		{
			Iterator iter = getEncodings();
			if (iter.hasNext())
			{
				object enc = iter.next();
				if (enc is string)
				{
				return getEncoded((string)enc);
				}
			}
			return null;
		}

		/// <summary>
		/// Returns the encoded form of this certification path, using
		/// the specified encoding.
		/// </summary>
		/// <param name="encoding"> the name of the encoding to use </param>
		/// <returns> the encoded bytes </returns>
		/// <exception cref="java.security.cert.CertificateEncodingException"> if an encoding error
		/// occurs or the encoding requested is not supported
		/// 
		///  </exception>
		public virtual byte[] getEncoded(string encoding)
		{
			if (encoding.Equals("PkiPath", StringComparison.OrdinalIgnoreCase))
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				ListIterator iter = certificates.listIterator(certificates.size());
				while (iter.hasPrevious())
				{
					v.add(toASN1Object((X509Certificate)iter.previous()));
				}

				return toDEREncoded(new DERSequence(v));
			}
			else if (encoding.Equals("PKCS7", StringComparison.OrdinalIgnoreCase))
			{
				ContentInfo encInfo = new ContentInfo(PKCSObjectIdentifiers_Fields.data, null);

				ASN1EncodableVector v = new ASN1EncodableVector();
				for (int i = 0; i != certificates.size(); i++)
				{
					v.add(toASN1Object((X509Certificate)certificates.get(i)));
				}

				SignedData sd = new SignedData(new ASN1Integer(1), new DERSet(), encInfo, new DERSet(v), null, new DERSet());

				return toDEREncoded(new ContentInfo(PKCSObjectIdentifiers_Fields.signedData, sd));
			}
			else if (encoding.Equals("PEM", StringComparison.OrdinalIgnoreCase))
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				PemWriter pWrt = new PemWriter(new OutputStreamWriter(bOut));

				try
				{
					for (int i = 0; i != certificates.size(); i++)
					{
						pWrt.writeObject(new PemObject("CERTIFICATE", ((X509Certificate)certificates.get(i)).getEncoded()));
					}

					pWrt.close();
				}
				catch (Exception)
				{
					throw new CertificateEncodingException("can't encode certificate for PEM encoded path");
				}

				return bOut.toByteArray();
			}
			else
			{
				throw new CertificateEncodingException("unsupported encoding: " + encoding);
			}
		}

		/// <summary>
		/// Returns the list of certificates in this certification
		/// path. The List returned must be immutable and thread-safe. 
		/// </summary>
		/// <returns> an immutable List of Certificates (may be empty, but not null)
		///  </returns>
		public virtual List getCertificates()
		{
			return Collections.unmodifiableList(new ArrayList(certificates));
		}

		/// <summary>
		/// Return a DERObject containing the encoded certificate.
		/// </summary>
		/// <param name="cert"> the X509Certificate object to be encoded
		/// </param>
		/// <returns> the DERObject
		///  </returns>
		private ASN1Primitive toASN1Object(X509Certificate cert)
		{
			try
			{
				return (new ASN1InputStream(cert.getEncoded())).readObject();
			}
			catch (Exception e)
			{
				throw new CertificateEncodingException("Exception while encoding certificate: " + e.ToString());
			}
		}

		private byte[] toDEREncoded(ASN1Encodable obj)
		{
			try
			{
				return obj.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new CertificateEncodingException("Exception thrown: " + e);
			}
		}
	}

}