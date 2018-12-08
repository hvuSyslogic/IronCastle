using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.x509
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V1TBSCertificateGenerator = org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using CertificateFactory = org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using X509Principal = org.bouncycastle.jce.X509Principal;

	/// <summary>
	/// class to produce an X.509 Version 1 certificate. </summary>
	/// @deprecated use org.bouncycastle.cert.X509v1CertificateBuilder. 
	public class X509V1CertificateGenerator
	{
		private readonly JcaJceHelper bcHelper = new BCJcaJceHelper(); // needed to force provider loading
		private readonly CertificateFactory certificateFactory = new CertificateFactory();

		private V1TBSCertificateGenerator tbsGen;
		private ASN1ObjectIdentifier sigOID;
		private AlgorithmIdentifier sigAlgId;
		private string signatureAlgorithm;

		public X509V1CertificateGenerator()
		{
			tbsGen = new V1TBSCertificateGenerator();
		}

		/// <summary>
		/// reset the generator
		/// </summary>
		public virtual void reset()
		{
			tbsGen = new V1TBSCertificateGenerator();
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
				tbsGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
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
				throw new IllegalArgumentException("Unknown signature type requested");
			}

			sigAlgId = X509Util.getSigAlgID(sigOID, signatureAlgorithm);

			tbsGen.setSignature(sigAlgId);
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
		/// using the default provider "BC" and the passed in source of randomness </summary>
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
		/// using the passed in provider for the signing, and the passed in source
		/// of randomness (if required). </summary>
		/// @deprecated use generate() 
		public virtual X509Certificate generateX509Certificate(PrivateKey key, string provider)
		{
			return generateX509Certificate(key, provider, null);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing, and the passed in source
		/// of randomness (if required). </summary>
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
		/// using the default provider and the passed in source of randomness
		/// <para>
		/// <b>Note:</b> this differs from the deprecated method in that the default provider is
		/// used - not "BC".
		/// </para>
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, SecureRandom random)
		{
			TBSCertificate tbsCert = tbsGen.generateTBSCertificate();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, key, random, tbsCert);
			}
			catch (IOException e)
			{
				throw new ExtCertificateEncodingException("exception encoding TBS cert", e);
			}

			return generateJcaObject(tbsCert, signature);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing, and the passed in source
		/// of randomness (if required).
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, string provider)
		{
			return generate(key, provider, null);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject,
		/// using the passed in provider for the signing, and the passed in source
		/// of randomness (if required).
		/// </summary>
		public virtual X509Certificate generate(PrivateKey key, string provider, SecureRandom random)
		{
			TBSCertificate tbsCert = tbsGen.generateTBSCertificate();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, provider, key, random, tbsCert);
			}
			catch (IOException e)
			{
				throw new ExtCertificateEncodingException("exception encoding TBS cert", e);
			}

			return generateJcaObject(tbsCert, signature);
		}

		private X509Certificate generateJcaObject(TBSCertificate tbsCert, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			try
			{
				return (X509Certificate)certificateFactory.engineGenerateCertificate(new ByteArrayInputStream((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
			}
			catch (Exception e)
			{
				throw new ExtCertificateEncodingException("exception producing certificate object", e);
			}
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