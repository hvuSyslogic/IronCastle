using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V2TBSCertListGenerator = org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using X509ExtensionsGenerator = org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using BCJcaJceHelper = org.bouncycastle.jcajce.util.BCJcaJceHelper;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using X509Principal = org.bouncycastle.jce.X509Principal;
	using X509CRLObject = org.bouncycastle.jce.provider.X509CRLObject;

	/// <summary>
	/// class to produce an X.509 Version 2 CRL. </summary>
	///  @deprecated use org.bouncycastle.cert.X509v2CRLBuilder. 
	public class X509V2CRLGenerator
	{
		private readonly JcaJceHelper bcHelper = new BCJcaJceHelper(); // needed to force provider loading

		private V2TBSCertListGenerator tbsGen;
		private ASN1ObjectIdentifier sigOID;
		private AlgorithmIdentifier sigAlgId;
		private string signatureAlgorithm;
		private X509ExtensionsGenerator extGenerator;

		public X509V2CRLGenerator()
		{
			tbsGen = new V2TBSCertListGenerator();
			extGenerator = new X509ExtensionsGenerator();
		}

		/// <summary>
		/// reset the generator
		/// </summary>
		public virtual void reset()
		{
			tbsGen = new V2TBSCertListGenerator();
			extGenerator.reset();
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

		public virtual void setThisUpdate(DateTime date)
		{
			tbsGen.setThisUpdate(new Time(date));
		}

		public virtual void setNextUpdate(DateTime date)
		{
			tbsGen.setNextUpdate(new Time(date));
		}

		/// <summary>
		/// Reason being as indicated by CRLReason, i.e. CRLReason.keyCompromise
		/// or 0 if CRLReason is not to be used
		/// 
		/// </summary>
		public virtual void addCRLEntry(BigInteger userCertificate, DateTime revocationDate, int reason)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificate), new Time(revocationDate), reason);
		}

		/// <summary>
		/// Add a CRL entry with an Invalidity Date extension as well as a CRLReason extension.
		/// Reason being as indicated by CRLReason, i.e. CRLReason.keyCompromise
		/// or 0 if CRLReason is not to be used
		/// 
		/// </summary>
		public virtual void addCRLEntry(BigInteger userCertificate, DateTime revocationDate, int reason, DateTime invalidityDate)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificate), new Time(revocationDate), reason, new ASN1GeneralizedTime(invalidityDate));
		}

		/// <summary>
		/// Add a CRL entry with extensions.
		/// 
		/// </summary>
		public virtual void addCRLEntry(BigInteger userCertificate, DateTime revocationDate, X509Extensions extensions)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificate), new Time(revocationDate), Extensions.getInstance(extensions));
		}

		/// <summary>
		/// Add the CRLEntry objects contained in a previous CRL.
		/// </summary>
		/// <param name="other"> the X509CRL to source the other entries from.  </param>
		public virtual void addCRL(X509CRL other)
		{
			Set revocations = other.getRevokedCertificates();

			if (revocations != null)
			{
				Iterator it = revocations.iterator();
				while (it.hasNext())
				{
					X509CRLEntry entry = (X509CRLEntry)it.next();

					ASN1InputStream aIn = new ASN1InputStream(entry.getEncoded());

					try
					{
						tbsGen.addCRLEntry(ASN1Sequence.getInstance(aIn.readObject()));
					}
					catch (IOException e)
					{
						throw new CRLException("exception processing encoding of CRL: " + e.ToString());
					}
				}
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
		/// add a given extension field for the standard extensions tag (tag 0)
		/// </summary>
		public virtual void addExtension(string oid, bool critical, ASN1Encodable value)
		{
			this.addExtension(new ASN1ObjectIdentifier(oid), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 0)
		/// </summary>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, ASN1Encodable value)
		{
			extGenerator.addExtension(new ASN1ObjectIdentifier(oid.getId()), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 0)
		/// </summary>
		public virtual void addExtension(string oid, bool critical, byte[] value)
		{
			this.addExtension(new ASN1ObjectIdentifier(oid), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 0)
		/// </summary>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, byte[] value)
		{
			extGenerator.addExtension(new ASN1ObjectIdentifier(oid.getId()), critical, value);
		}

		/// <summary>
		/// generate an X509 CRL, based on the current issuer and subject
		/// using the default provider "BC". </summary>
		/// @deprecated use generate(key, "BC") 
		public virtual X509CRL generateX509CRL(PrivateKey key)
		{
			try
			{
				return generateX509CRL(key, "BC", null);
			}
			catch (NoSuchProviderException)
			{
				throw new SecurityException("BC provider not installed!");
			}
		}

		/// <summary>
		/// generate an X509 CRL, based on the current issuer and subject
		/// using the default provider "BC" and an user defined SecureRandom object as
		/// source of randomness. </summary>
		/// @deprecated use generate(key, random, "BC") 
		public virtual X509CRL generateX509CRL(PrivateKey key, SecureRandom random)
		{
			try
			{
				return generateX509CRL(key, "BC", random);
			}
			catch (NoSuchProviderException)
			{
				throw new SecurityException("BC provider not installed!");
			}
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the passed in provider for the signing. </summary>
		/// @deprecated use generate() 
		public virtual X509CRL generateX509CRL(PrivateKey key, string provider)
		{
			return generateX509CRL(key, provider, null);
		}

		/// <summary>
		/// generate an X509 CRL, based on the current issuer and subject,
		/// using the passed in provider for the signing. </summary>
		/// @deprecated use generate() 
		public virtual X509CRL generateX509CRL(PrivateKey key, string provider, SecureRandom random)
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
		/// generate an X509 CRL, based on the current issuer and subject
		/// using the default provider.
		/// <para>
		/// <b>Note:</b> this differs from the deprecated method in that the default provider is
		/// used - not "BC".
		/// </para>
		/// </summary>
		public virtual X509CRL generate(PrivateKey key)
		{
			return generate(key, (SecureRandom)null);
		}

		/// <summary>
		/// generate an X509 CRL, based on the current issuer and subject
		/// using the default provider and an user defined SecureRandom object as
		/// source of randomness.
		/// <para>
		/// <b>Note:</b> this differs from the deprecated method in that the default provider is
		/// used - not "BC".
		/// </para>
		/// </summary>
		public virtual X509CRL generate(PrivateKey key, SecureRandom random)
		{
			TBSCertList tbsCrl = generateCertList();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, key, random, tbsCrl);
			}
			catch (IOException e)
			{
				throw new ExtCRLException("cannot generate CRL encoding", e);
			}

			return generateJcaObject(tbsCrl, signature);
		}

		/// <summary>
		/// generate an X509 certificate, based on the current issuer and subject
		/// using the passed in provider for the signing.
		/// </summary>
		public virtual X509CRL generate(PrivateKey key, string provider)
		{
			return generate(key, provider, null);
		}

		/// <summary>
		/// generate an X509 CRL, based on the current issuer and subject,
		/// using the passed in provider for the signing.
		/// </summary>
		public virtual X509CRL generate(PrivateKey key, string provider, SecureRandom random)
		{
			TBSCertList tbsCrl = generateCertList();
			byte[] signature;

			try
			{
				signature = X509Util.calculateSignature(sigOID, signatureAlgorithm, provider, key, random, tbsCrl);
			}
			catch (IOException e)
			{
				throw new ExtCRLException("cannot generate CRL encoding", e);
			}

			return generateJcaObject(tbsCrl, signature);
		}

		private TBSCertList generateCertList()
		{
			if (!extGenerator.isEmpty())
			{
				tbsGen.setExtensions(extGenerator.generate());
			}

			return tbsGen.generateTBSCertList();
		}

		private X509CRL generateJcaObject(TBSCertList tbsCrl, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCrl);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			return new X509CRLObject(new CertificateList(new DERSequence(v)));
		}

		/// <summary>
		/// Return an iterator of the signature names supported by the generator.
		/// </summary>
		/// <returns> an iterator containing recognised names. </returns>
		public virtual Iterator getSignatureAlgNames()
		{
			return X509Util.getAlgNames();
		}

		public class ExtCRLException : CRLException
		{
			internal Exception cause;

			public ExtCRLException(string message, Exception cause) : base(message)
			{
				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}

}