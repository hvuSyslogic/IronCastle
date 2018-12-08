using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.oiw;

using System;

namespace org.bouncycastle.tsp
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using ESSCertID = org.bouncycastle.asn1.ess.ESSCertID;
	using ESSCertIDv2 = org.bouncycastle.asn1.ess.ESSCertIDv2;
	using SigningCertificate = org.bouncycastle.asn1.ess.SigningCertificate;
	using SigningCertificateV2 = org.bouncycastle.asn1.ess.SigningCertificateV2;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TSTInfo = org.bouncycastle.asn1.tsp.TSTInfo;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessable = org.bouncycastle.cms.CMSProcessable;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using SignerId = org.bouncycastle.cms.SignerId;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationVerifier = org.bouncycastle.cms.SignerInformationVerifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// Carrier class for a TimeStampToken.
	/// </summary>
	public class TimeStampToken
	{
		internal CMSSignedData tsToken;

		internal SignerInformation tsaSignerInfo;

		internal DateTime genTime;

		internal TimeStampTokenInfo tstInfo;

		internal CertID certID;

		public TimeStampToken(ContentInfo contentInfo) : this(getSignedData(contentInfo))
		{
		}

		private static CMSSignedData getSignedData(ContentInfo contentInfo)
		{
			try
			{
				return new CMSSignedData(contentInfo);
			}
			catch (CMSException e)
			{
				throw new TSPException("TSP parsing error: " + e.Message, e.InnerException);
			}
		}

		public TimeStampToken(CMSSignedData signedData)
		{
			this.tsToken = signedData;

			if (!this.tsToken.getSignedContentTypeOID().Equals(PKCSObjectIdentifiers_Fields.id_ct_TSTInfo.getId()))
			{
				throw new TSPValidationException("ContentInfo object not for a time stamp.");
			}

			Collection signers = tsToken.getSignerInfos().getSigners();

			if (signers.size() != 1)
			{
				throw new IllegalArgumentException("Time-stamp token signed by " + signers.size() + " signers, but it must contain just the TSA signature.");
			}

			tsaSignerInfo = (SignerInformation)signers.iterator().next();

			try
			{
				CMSProcessable content = tsToken.getSignedContent();
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();

				content.write(bOut);

				ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bOut.toByteArray()));

				this.tstInfo = new TimeStampTokenInfo(TSTInfo.getInstance(aIn.readObject()));

				Attribute attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificate);

				if (attr != null)
				{
					SigningCertificate signCert = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0));

					this.certID = new CertID(this, ESSCertID.getInstance(signCert.getCerts()[0]));
				}
				else
				{
					attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers_Fields.id_aa_signingCertificateV2);

					if (attr == null)
					{
						throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
					}

					SigningCertificateV2 signCertV2 = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0));

					this.certID = new CertID(this, ESSCertIDv2.getInstance(signCertV2.getCerts()[0]));
				}
			}
			catch (CMSException e)
			{
				throw new TSPException(e.Message, e.getUnderlyingException());
			}
		}

		public virtual TimeStampTokenInfo getTimeStampInfo()
		{
			return tstInfo;
		}

		public virtual SignerId getSID()
		{
			return tsaSignerInfo.getSID();
		}

		public virtual AttributeTable getSignedAttributes()
		{
			return tsaSignerInfo.getSignedAttributes();
		}

		public virtual AttributeTable getUnsignedAttributes()
		{
			return tsaSignerInfo.getUnsignedAttributes();
		}

		public virtual Store getCertificates()
		{
			return tsToken.getCertificates();
		}

		public virtual Store getCRLs()
		{
			return tsToken.getCRLs();
		}

		public virtual Store getAttributeCertificates()
		{
			return tsToken.getAttributeCertificates();
		}

		/// <summary>
		/// Validate the time stamp token.
		/// <para>
		/// To be valid the token must be signed by the passed in certificate and
		/// the certificate must be the one referred to by the SigningCertificate
		/// attribute included in the hashed attributes of the token. The
		/// certificate must also have the ExtendedKeyUsageExtension with only
		/// KeyPurposeId.id_kp_timeStamping and have been valid at the time the
		/// timestamp was created.
		/// </para>
		/// <para>
		/// A successful call to validate means all the above are true.
		/// </para>
		/// </summary>
		/// <param name="sigVerifier"> the content verifier create the objects required to verify the CMS object in the timestamp. </param>
		/// <exception cref="TSPException"> if an exception occurs in processing the token. </exception>
		/// <exception cref="TSPValidationException"> if the certificate or signature fail to be valid. </exception>
		/// <exception cref="IllegalArgumentException"> if the sigVerifierProvider has no associated certificate. </exception>
		public virtual void validate(SignerInformationVerifier sigVerifier)
		{
			if (!sigVerifier.hasAssociatedCertificate())
			{
				throw new IllegalArgumentException("verifier provider needs an associated certificate");
			}

			try
			{
				X509CertificateHolder certHolder = sigVerifier.getAssociatedCertificate();
				DigestCalculator calc = sigVerifier.getDigestCalculator(certID.getHashAlgorithm());

				OutputStream cOut = calc.getOutputStream();

				cOut.write(certHolder.getEncoded());
				cOut.close();

				if (!Arrays.constantTimeAreEqual(certID.getCertHash(), calc.getDigest()))
				{
					throw new TSPValidationException("certificate hash does not match certID hash.");
				}

				if (certID.getIssuerSerial() != null)
				{
					IssuerAndSerialNumber issuerSerial = new IssuerAndSerialNumber(certHolder.toASN1Structure());

					if (!certID.getIssuerSerial().getSerial().Equals(issuerSerial.getSerialNumber()))
					{
						throw new TSPValidationException("certificate serial number does not match certID for signature.");
					}

					GeneralName[] names = certID.getIssuerSerial().getIssuer().getNames();
					bool found = false;

					for (int i = 0; i != names.Length; i++)
					{
						if (names[i].getTagNo() == 4 && X500Name.getInstance(names[i].getName()).Equals(X500Name.getInstance(issuerSerial.getName())))
						{
							found = true;
							break;
						}
					}

					if (!found)
					{
						throw new TSPValidationException("certificate name does not match certID for signature. ");
					}
				}

				TSPUtil.validateCertificate(certHolder);

				if (!certHolder.isValidOn(tstInfo.getGenTime()))
				{
					throw new TSPValidationException("certificate not valid when time stamp created.");
				}

				if (!tsaSignerInfo.verify(sigVerifier))
				{
					throw new TSPValidationException("signature not created by certificate.");
				}
			}
			catch (CMSException e)
			{
				if (e.getUnderlyingException() != null)
				{
					throw new TSPException(e.Message, e.getUnderlyingException());
				}
				else
				{
					throw new TSPException("CMS exception: " + e, e);
				}
			}
			catch (IOException e)
			{
				throw new TSPException("problem processing certificate: " + e, e);
			}
			catch (OperatorCreationException e)
			{
				throw new TSPException("unable to create digest: " + e.Message, e);
			}
		}

		/// <summary>
		/// Return true if the signature on time stamp token is valid.
		/// <para>
		/// Note: this is a much weaker proof of correctness than calling validate().
		/// </para>
		/// </summary>
		/// <param name="sigVerifier"> the content verifier create the objects required to verify the CMS object in the timestamp. </param>
		/// <returns> true if the signature matches, false otherwise. </returns>
		/// <exception cref="TSPException"> if the signature cannot be processed or the provider cannot match the algorithm. </exception>
		public virtual bool isSignatureValid(SignerInformationVerifier sigVerifier)
		{
			try
			{
				return tsaSignerInfo.verify(sigVerifier);
			}
			catch (CMSException e)
			{
				if (e.getUnderlyingException() != null)
				{
					throw new TSPException(e.Message, e.getUnderlyingException());
				}
				else
				{
					throw new TSPException("CMS exception: " + e, e);
				}
			}
		}

		/// <summary>
		/// Return the underlying CMSSignedData object.
		/// </summary>
		/// <returns> the underlying CMS structure. </returns>
		public virtual CMSSignedData toCMSSignedData()
		{
			return tsToken;
		}

		/// <summary>
		/// Return a ASN.1 encoded byte stream representing the encoded object.
		/// </summary>
		/// <exception cref="IOException"> if encoding fails. </exception>
		public virtual byte[] getEncoded()
		{
			return tsToken.getEncoded();
		}

		// perhaps this should be done using an interface on the ASN.1 classes...
		public class CertID
		{
			private readonly TimeStampToken outerInstance;

			internal ESSCertID certID;
			internal ESSCertIDv2 certIDv2;

			public CertID(TimeStampToken outerInstance, ESSCertID certID)
			{
				this.outerInstance = outerInstance;
				this.certID = certID;
				this.certIDv2 = null;
			}

			public CertID(TimeStampToken outerInstance, ESSCertIDv2 certID)
			{
				this.outerInstance = outerInstance;
				this.certIDv2 = certID;
				this.certID = null;
			}

			public virtual string getHashAlgorithmName()
			{
				if (certID != null)
				{
					return "SHA-1";
				}
				else
				{
					if (NISTObjectIdentifiers_Fields.id_sha256.Equals(certIDv2.getHashAlgorithm().getAlgorithm()))
					{
						return "SHA-256";
					}
					return certIDv2.getHashAlgorithm().getAlgorithm().getId();
				}
			}

			public virtual AlgorithmIdentifier getHashAlgorithm()
			{
				if (certID != null)
				{
					return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
				}
				else
				{
					return certIDv2.getHashAlgorithm();
				}
			}

			public virtual byte[] getCertHash()
			{
				if (certID != null)
				{
					return certID.getCertHash();
				}
				else
				{
					return certIDv2.getCertHash();
				}
			}

			public virtual IssuerSerial getIssuerSerial()
			{
				if (certID != null)
				{
					return certID.getIssuerSerial();
				}
				else
				{
					return certIDv2.getIssuerSerial();
				}
			}
		}
	}

}