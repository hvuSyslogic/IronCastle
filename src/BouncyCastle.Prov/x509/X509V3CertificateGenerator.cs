using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using X509ExtensionsGenerator = org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using CertificateFactory = org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using X509Principal = org.bouncycastle.jce.X509Principal;
	using X509ExtensionUtil = org.bouncycastle.x509.extension.X509ExtensionUtil;

	/// <summary>
	/// class to produce an X.509 Version 3 certificate. </summary>
	///  @deprecated use org.bouncycastle.cert.X509v3CertificateBuilder. 
	public class X509V3CertificateGenerator
	{
		private readonly JcaJceHelper bcHelper = new BCJcaJceHelper(); // needed to force provider loading
		private readonly CertificateFactory certificateFactory = new CertificateFactory();

		private V3TBSCertificateGenerator tbsGen;
		private ASN1ObjectIdentifier sigOID;
		private AlgorithmIdentifier sigAlgId;
		private string signatureAlgorithm;
		private X509ExtensionsGenerator extGenerator;

		public X509V3CertificateGenerator()
		{
			tbsGen = new V3TBSCertificateGenerator();
			extGenerator = new X509ExtensionsGenerator();
		}

		/// <summary>
		/// reset the generator
		/// </summary>
		public virtual void reset()
		{
			tbsGen = new V3TBSCertificateGenerator();
			extGenerator.reset();
		}

		/// <summary>
		/// set the serial number for the certificate.
		/// </summary>
		public virtual void setSerialNumber(BigInteger serialNumber)
		{
			if (serialNumber.compareTo(BigInteger.ZERO) <= 0)
			{
				throw new IllegalArgumentException("serial number must be a positive integer");
			}

			tbsGen.setSerialNumber(new ASN1Integer(serialNumber));
		}

		/// <summary>
		/// Set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
		/// certificate.
		/// </summary>
		public virtual void setIssuerDN(X500Principal issuer)
		{
			try
			{
				tbsGen.setIssuer(new X509Principal(issuer.getEncoded()));
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("can't process principal: " + e);
			}
		}

		/// <summary>
		/// Set the issuer distinguished name - the issuer is the entity whose private key is used to sign the
		/// certificate.
		/// </summary>
		public virtual void setIssuerDN(X509Name issuer)
		{
			tbsGen.setIssuer(issuer);
		}

		public virtual void setNotBefore(DateTime date)
		{
			tbsGen.setStartDate(new Time(date));
		}

		public virtual void setNotAfter(DateTime date)
		{
			tbsGen.setEndDate(new Time(date));
		}

		/// <summary>
		/// Set the subject distinguished name. The subject describes the entity associated with the public key.
		/// </summary>
		public virtual void setSubjectDN(X500Principal subject)
		{
			try
			{
				tbsGen.setSubject(new X509Principal(subject.getEncoded()));
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("can't process principal: " + e);
			}
		}

		/// <summary>
		/// Set the subject distinguished name. The subject describes the entity associated with the public key.
		/// </summary>
		public virtual void setSubjectDN(X509Name subject)
		{
			tbsGen.setSubject(subject);
		}

		public virtual void setPublicKey(PublicKey key)
		{
			try
			{
				tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance((new ASN1InputStream(key.getEncoded())).readObject()));
			}
			catch (Exception e)
			{
				throw new IllegalArgumentException("unable to process key - " + e.ToString());
			}
		}

		/// <summary>
		/// Set the signature algorithm. This can be either a name or an OID, names
		/// are treated as case insensitive.
		/// </summary>
		/// <param name="signatureAlgorithm"> string representation of the algorithm name. </param>
		public virtual void setSignatureAlgorithm(string signatureAlgorithm)
		{
			this.signatureAlgorithm = signatureAlgorithm;

			try
			{
				sigOID = X509Util.getAlgorithmOID(signatureAlgorithm);
			}
			catch (Exception)
			{
				throw new IllegalArgumentException("Unknown signature type requested: " + signatureAlgorithm);
			}

			sigAlgId = X509Util.getSigAlgID(sigOID, signatureAlgorithm);

			tbsGen.setSignature(sigAlgId);
		}

		/// <summary>
		/// Set the subject unique ID - note: it is very rare that it is correct to do this.
		/// </summary>
		public virtual void setSubjectUniqueID(bool[] uniqueID)
		{
			tbsGen.setSubjectUniqueID(booleanToBitString(uniqueID));
		}

		/// <summary>
		/// Set the issuer unique ID - note: it is very rare that it is correct to do this.
		/// </summary>
		public virtual void setIssuerUniqueID(bool[] uniqueID)
		{
			tbsGen.setIssuerUniqueID(booleanToBitString(uniqueID));
		}

		private DERBitString booleanToBitString(bool[] id)
		{
			byte[] bytes = new byte[(id.Length + 7) / 8];

			for (int i = 0; i != id.Length; i++)
			{
				bytes[i / 8] |= (byte)((id[i]) ? (1 << ((7 - (i % 8)))) : 0);
			}

			int pad = id.Length % 8;

			if (pad == 0)
			{
				return new DERBitString(bytes);
			}
			else
			{
				return new DERBitString(bytes, 8 - pad);
			}
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// </summary>
		public virtual void addExtension(string oid, bool critical, ASN1Encodable value)
		{
			this.addExtension(new ASN1ObjectIdentifier(oid), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// </summary>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, ASN1Encodable value)
		{
			extGenerator.addExtension(new ASN1ObjectIdentifier(oid.getId()), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// The value parameter becomes the contents of the octet string associated
		/// with the extension.
		/// </summary>
		public virtual void addExtension(string oid, bool critical, byte[] value)
		{
			this.addExtension(new ASN1ObjectIdentifier(oid), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// </summary>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, byte[] value)
		{
			extGenerator.addExtension(new ASN1ObjectIdentifier(oid.getId()), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// copying the extension value from another certificate. </summary>
		/// <exception cref="CertificateParsingException"> if the extension cannot be extracted. </exception>
		public virtual void copyAndAddExtension(string oid, bool critical, X509Certificate cert)
		{
			byte[] extValue = cert.getExtensionValue(oid);

			if (extValue == null)
			{
				throw new CertificateParsingException("extension " + oid + " not present");
			}

			try
			{
				ASN1Encodable value = X509ExtensionUtil.fromExtensionValue(extValue);

				this.addExtension(oid, critical, value);
			}
			catch (IOException e)
			{
				throw new CertificateParsingException(e.ToString());
			}
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3)
		/// copying the extension value from another certificate. </summary>
		/// <exception cref="CertificateParsingException"> if the extension cannot be extracted. </exception>
		public virtual void copyAndAddExtension(ASN1ObjectIdentifier oid, bool critical, X509Certificate cert)
		{
			this.copyAndAddExtension(oid.getId(), critical, cert);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the default provider "BC". </summary>
		/// @deprecated use generate(key, "BC") 
		public virtual X509Certificate generateX509Certificate(PrivateKey key)
		{
			try
			{
				return generateX509Certificate(key, "BC", null);
			}
			catch (NoSuchProviderException)
			{
				throw new SecurityException("BC provider not installed!");
			}
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the default provider "BC", and the passed in source of randomness
		/// (if required). </summary>
		/// @deprecated use generate(key, random, "BC") 
		public virtual X509Certificate generateX509Certificate(PrivateKey key, SecureRandom random)
		{
			try
			{
				return generateX509Certificate(key, "BC", random);
			}
			catch (NoSuchProviderException)
			{
				throw new SecurityException("BC provider not installed!");
			}
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing. </summary>
		/// @deprecated use generate() 
		public virtual X509Certificate generateX509Certificate(PrivateKey key, string provider)
		{
			return generateX509Certificate(key, provider, null);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing and the supplied source
		/// of randomness, if required. </summary>
		/// @deprecated use generate() 
		public virtual X509Certificate generateX509Certificate(PrivateKey key, string provider, SecureRandom random)
		{
			try
			{
				return generate(key, provider, random);
			}
			catch (NoSuchProviderException e)
			{
				throw e;
			}
			catch (SignatureException e)
			{
				throw e;
			}
			catch (InvalidKeyException e)
			{
				throw e;
			}
			catch (GeneralSecurityException e)
			{
				throw new SecurityException("exception: " + e);
			}
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the default provider.
		/// <para>
		/// <b>Note:</b> this differs from the deprecated method in that the default provider is
		/// used - not "BC".
		/// </para>
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key)
		{
			return generate(key, (SecureRandom)null);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the default provider, and the passed in source of randomness
		/// (if required).
		/// <para>
		/// <b>Note:</b> this differs from the deprecated method in that the default provider is
		/// used - not "BC".
		/// </para>
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, SecureRandom random)
		{
			TBSCertificate tbsCert = generateTbsCert();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, key, random, tbsCert);
			}
			catch (IOException e)
			{
				throw new ExtCertificateEncodingException("exception encoding TBS cert", e);
			}

			try
			{
				return generateJcaObject(tbsCert, signature);
			}
			catch (Exception e)
			{
				throw new ExtCertificateEncodingException("exception producing certificate object", e);
			}
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing.
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, string provider)
		{
			return generate(key, provider, null);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing and the supplied source
		/// of randomness, if required.
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, string provider, SecureRandom random)
		{
			TBSCertificate tbsCert = generateTbsCert();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, provider, key, random, tbsCert);
			}
			catch (IOException e)
			{
				throw new ExtCertificateEncodingException("exception encoding TBS cert", e);
			}

			try
			{
				return generateJcaObject(tbsCert, signature);
			}
			catch (Exception e)
			{
				throw new ExtCertificateEncodingException("exception producing certificate object", e);
			}
		}

		private TBSCertificate generateTbsCert()
		{
			if (!extGenerator.isEmpty())
			{
				tbsGen.setExtensions(extGenerator.generate());
			}

			return tbsGen.generateTBSCertificate();
		}

		private X509Certificate generateJcaObject(TBSCertificate tbsCert, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			return (X509Certificate)certificateFactory.engineGenerateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
		}

		/// <summary>
		/// Return an iterator of the signature names supported by the generator.
		/// </summary>
		/// <returns> an iterator containing recognised names. </returns>
		public virtual Iterator getSignatureAlgNames()
		{
			return X509Util.getAlgNames();
		}
	}

}