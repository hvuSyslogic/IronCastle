using org.bouncycastle.cms;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BERSequence = org.bouncycastle.asn1.BERSequence;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using SignedData = org.bouncycastle.asn1.cms.SignedData;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Encodable = org.bouncycastle.util.Encodable;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// general class for handling a pkcs7-signature message.
	/// 
	/// A simple example of usage - note, in the example below the validity of
	/// the certificate isn't verified, just the fact that one of the certs 
	/// matches the given signer...
	/// 
	/// <pre>
	///  Store                   certStore = s.getCertificates();
	///  SignerInformationStore  signers = s.getSignerInfos();
	///  Collection              c = signers.getSigners();
	///  Iterator                it = c.iterator();
	/// 
	///  while (it.hasNext())
	///  {
	///      SignerInformation   signer = (SignerInformation)it.next();
	///      Collection          certCollection = certStore.getMatches(signer.getSID());
	/// 
	///      Iterator              certIt = certCollection.iterator();
	///      X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
	/// 
	///      if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
	///      {
	///          verified++;
	///      }   
	///  }
	/// </pre>
	/// </summary>
	public class CMSSignedData : Encodable
	{
		private static readonly CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;

		internal SignedData signedData;
		internal ContentInfo contentInfo;
		internal CMSTypedData signedContent;
		internal SignerInformationStore signerInfoStore;

		private Map hashes;

		private CMSSignedData(CMSSignedData c)
		{
			this.signedData = c.signedData;
			this.contentInfo = c.contentInfo;
			this.signedContent = c.signedContent;
			this.signerInfoStore = c.signerInfoStore;
		}

		public CMSSignedData(byte[] sigBlock) : this(CMSUtils.readContentInfo(sigBlock))
		{
		}

		public CMSSignedData(CMSProcessable signedContent, byte[] sigBlock) : this(signedContent, CMSUtils.readContentInfo(sigBlock))
		{
		}

		/// <summary>
		/// Content with detached signature, digests precomputed
		/// </summary>
		/// <param name="hashes"> a map of precomputed digests for content indexed by name of hash. </param>
		/// <param name="sigBlock"> the signature object. </param>
		public CMSSignedData(Map hashes, byte[] sigBlock) : this(hashes, CMSUtils.readContentInfo(sigBlock))
		{
		}

		/// <summary>
		/// base constructor - content with detached signature.
		/// </summary>
		/// <param name="signedContent"> the content that was signed. </param>
		/// <param name="sigData"> the signature object. </param>
		public CMSSignedData(CMSProcessable signedContent, InputStream sigData) : this(signedContent, CMSUtils.readContentInfo(new ASN1InputStream(sigData)))
		{
		}

		/// <summary>
		/// base constructor - with encapsulated content
		/// </summary>
		public CMSSignedData(InputStream sigData) : this(CMSUtils.readContentInfo(sigData))
		{
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public CMSSignedData(final CMSProcessable signedContent, org.bouncycastle.asn1.cms.ContentInfo sigData) throws CMSException
		public CMSSignedData(CMSProcessable signedContent, ContentInfo sigData)
		{
			if (signedContent is CMSTypedData)
			{
				this.signedContent = (CMSTypedData)signedContent;
			}
			else
			{
				this.signedContent = new CMSTypedDataAnonymousInnerClass(this, signedContent);
			}

			this.contentInfo = sigData;
			this.signedData = getSignedData();
		}

		public class CMSTypedDataAnonymousInnerClass : CMSTypedData
		{
			private readonly CMSSignedData outerInstance;

			private CMSProcessable signedContent;

			public CMSTypedDataAnonymousInnerClass(CMSSignedData outerInstance, CMSProcessable signedContent)
			{
				this.outerInstance = outerInstance;
				this.signedContent = signedContent;
			}

			public ASN1ObjectIdentifier getContentType()
			{
				return outerInstance.signedData.getEncapContentInfo().getContentType();
			}

			public void write(OutputStream @out)
			{
				signedContent.write(@out);
			}

			public object getContent()
			{
				return signedContent.getContent();
			}
		}

		public CMSSignedData(Map hashes, ContentInfo sigData)
		{
			this.hashes = hashes;
			this.contentInfo = sigData;
			this.signedData = getSignedData();
		}

		public CMSSignedData(ContentInfo sigData)
		{
			this.contentInfo = sigData;
			this.signedData = getSignedData();

			//
			// this can happen if the signed message is sent simply to send a
			// certificate chain.
			//
			ASN1Encodable content = signedData.getEncapContentInfo().getContent();
			if (content != null)
			{
				if (content is ASN1OctetString)
				{
					this.signedContent = new CMSProcessableByteArray(signedData.getEncapContentInfo().getContentType(), ((ASN1OctetString)content).getOctets());
				}
				else
				{
					this.signedContent = new PKCS7ProcessableObject(signedData.getEncapContentInfo().getContentType(), content);
				}
			}
			else
			{
				this.signedContent = null;
			}
		}

		private SignedData getSignedData()
		{
			try
			{
				return SignedData.getInstance(contentInfo.getContent());
			}
			catch (ClassCastException e)
			{
				throw new CMSException("Malformed content.", e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CMSException("Malformed content.", e);
			}
		}

		/// <summary>
		/// Return the version number for this object
		/// </summary>
		public virtual int getVersion()
		{
			return signedData.getVersion().getValue().intValue();
		}

		/// <summary>
		/// return the collection of signers that are associated with the
		/// signatures for the message.
		/// </summary>
		public virtual SignerInformationStore getSignerInfos()
		{
			if (signerInfoStore == null)
			{
				ASN1Set s = signedData.getSignerInfos();
				List signerInfos = new ArrayList();

				for (int i = 0; i != s.size(); i++)
				{
					SignerInfo info = SignerInfo.getInstance(s.getObjectAt(i));
					ASN1ObjectIdentifier contentType = signedData.getEncapContentInfo().getContentType();

					if (hashes == null)
					{
						signerInfos.add(new SignerInformation(info, contentType, signedContent, null));
					}
					else
					{
						object obj = hashes.keySet().iterator().next();
						byte[] hash = (obj is string) ? (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm().getId()) : (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm());

						signerInfos.add(new SignerInformation(info, contentType, null, hash));
					}
				}

				signerInfoStore = new SignerInformationStore(signerInfos);
			}

			return signerInfoStore;
		}

		/// <summary>
		/// Return if this is object represents a detached signature.
		/// </summary>
		/// <returns> true if this message represents a detached signature, false otherwise. </returns>
		public virtual bool isDetachedSignature()
		{
			return signedData.getEncapContentInfo().getContent() == null && signedData.getSignerInfos().size() > 0;
		}

		/// <summary>
		/// Return if this is object represents a certificate management message.
		/// </summary>
		/// <returns> true if the message has no signers or content, false otherwise. </returns>
		public virtual bool isCertificateManagementMessage()
		{
			return signedData.getEncapContentInfo().getContent() == null && signedData.getSignerInfos().size() == 0;
		}

		/// <summary>
		/// Return any X.509 certificate objects in this SignedData structure as a Store of X509CertificateHolder objects.
		/// </summary>
		/// <returns> a Store of X509CertificateHolder objects. </returns>
		public virtual Store<X509CertificateHolder> getCertificates()
		{
			return HELPER.getCertificates(signedData.getCertificates());
		}

		/// <summary>
		/// Return any X.509 CRL objects in this SignedData structure as a Store of X509CRLHolder objects.
		/// </summary>
		/// <returns> a Store of X509CRLHolder objects. </returns>
		public virtual Store<X509CRLHolder> getCRLs()
		{
			return HELPER.getCRLs(signedData.getCRLs());
		}

		/// <summary>
		/// Return any X.509 attribute certificate objects in this SignedData structure as a Store of X509AttributeCertificateHolder objects.
		/// </summary>
		/// <returns> a Store of X509AttributeCertificateHolder objects. </returns>
		public virtual Store<X509AttributeCertificateHolder> getAttributeCertificates()
		{
			return HELPER.getAttributeCertificates(signedData.getCertificates());
		}

		/// <summary>
		/// Return any OtherRevocationInfo OtherRevInfo objects of the type indicated by otherRevocationInfoFormat in
		/// this SignedData structure.
		/// </summary>
		/// <param name="otherRevocationInfoFormat"> OID of the format type been looked for.
		/// </param>
		/// <returns> a Store of ASN1Encodable objects representing any objects of otherRevocationInfoFormat found. </returns>
		public virtual Store getOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat)
		{
			return HELPER.getOtherRevocationInfo(otherRevocationInfoFormat, signedData.getCRLs());
		}

		/// <summary>
		/// Return the digest algorithm identifiers for the SignedData object
		/// </summary>
		/// <returns> the set of digest algorithm identifiers </returns>
		public virtual Set<AlgorithmIdentifier> getDigestAlgorithmIDs()
		{
			Set<AlgorithmIdentifier> digests = new HashSet<AlgorithmIdentifier>(signedData.getDigestAlgorithms().size());

			for (Enumeration en = signedData.getDigestAlgorithms().getObjects(); en.hasMoreElements();)
			{
				digests.add(AlgorithmIdentifier.getInstance(en.nextElement()));
			}

			return Collections.unmodifiableSet(digests);
		}

		/// <summary>
		/// Return the a string representation of the OID associated with the
		/// encapsulated content info structure carried in the signed data.
		/// </summary>
		/// <returns> the OID for the content type. </returns>
		public virtual string getSignedContentTypeOID()
		{
			return signedData.getEncapContentInfo().getContentType().getId();
		}

		public virtual CMSTypedData getSignedContent()
		{
			return signedContent;
		}

		/// <summary>
		/// return the ContentInfo
		/// </summary>
		public virtual ContentInfo toASN1Structure()
		{
			return contentInfo;
		}

		/// <summary>
		/// return the ASN.1 encoded representation of this object.
		/// </summary>
		public virtual byte[] getEncoded()
		{
			return contentInfo.getEncoded();
		}

		/// <summary>
		/// Verify all the SignerInformation objects and their associated counter signatures attached
		/// to this CMS SignedData object.
		/// </summary>
		/// <param name="verifierProvider">  a provider of SignerInformationVerifier objects. </param>
		/// <returns> true if all verify, false otherwise. </returns>
		/// <exception cref="CMSException">  if an exception occurs during the verification process. </exception>
		public virtual bool verifySignatures(SignerInformationVerifierProvider verifierProvider)
		{
			return verifySignatures(verifierProvider, false);
		}

		/// <summary>
		/// Verify all the SignerInformation objects and optionally their associated counter signatures attached
		/// to this CMS SignedData object.
		/// </summary>
		/// <param name="verifierProvider">  a provider of SignerInformationVerifier objects. </param>
		/// <param name="ignoreCounterSignatures"> if true don't check counter signatures. If false check counter signatures as well. </param>
		/// <returns> true if all verify, false otherwise. </returns>
		/// <exception cref="CMSException">  if an exception occurs during the verification process. </exception>
		public virtual bool verifySignatures(SignerInformationVerifierProvider verifierProvider, bool ignoreCounterSignatures)
		{
			Collection signers = this.getSignerInfos().getSigners();

			for (Iterator it = signers.iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();

				try
				{
					SignerInformationVerifier verifier = verifierProvider.get(signer.getSID());

					if (!signer.verify(verifier))
					{
						return false;
					}

					if (!ignoreCounterSignatures)
					{
						Collection counterSigners = signer.getCounterSignatures().getSigners();

						for (Iterator cIt = counterSigners.iterator(); cIt.hasNext();)
						{
							if (!verifyCounterSignature((SignerInformation)cIt.next(), verifierProvider))
							{
								return false;
							}
						}
					}
				}
				catch (OperatorCreationException e)
				{
					throw new CMSException("failure in verifier provider: " + e.Message, e);
				}
			}

			return true;
		}

		private bool verifyCounterSignature(SignerInformation counterSigner, SignerInformationVerifierProvider verifierProvider)
		{
			SignerInformationVerifier counterVerifier = verifierProvider.get(counterSigner.getSID());

			if (!counterSigner.verify(counterVerifier))
			{
				return false;
			}

			Collection counterSigners = counterSigner.getCounterSignatures().getSigners();
			for (Iterator cIt = counterSigners.iterator(); cIt.hasNext();)
			{
				if (!verifyCounterSignature((SignerInformation)cIt.next(), verifierProvider))
				{
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Replace the SignerInformation store associated with this
		/// CMSSignedData object with the new one passed in. You would
		/// probably only want to do this if you wanted to change the unsigned 
		/// attributes associated with a signer, or perhaps delete one.
		/// </summary>
		/// <param name="signedData"> the signed data object to be used as a base. </param>
		/// <param name="signerInformationStore"> the new signer information store to use. </param>
		/// <returns> a new signed data object. </returns>
		public static CMSSignedData replaceSigners(CMSSignedData signedData, SignerInformationStore signerInformationStore)
		{
			//
			// copy
			//
			CMSSignedData cms = new CMSSignedData(signedData);

			//
			// replace the store
			//
			cms.signerInfoStore = signerInformationStore;

			//
			// replace the signers in the SignedData object
			//
			ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
			ASN1EncodableVector vec = new ASN1EncodableVector();

			Iterator it = signerInformationStore.getSigners().iterator();
			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation)it.next();
				digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
				vec.add(signer.toASN1Structure());
			}

			ASN1Set digests = new DERSet(digestAlgs);
			ASN1Set signers = new DERSet(vec);
			ASN1Sequence sD = (ASN1Sequence)signedData.signedData.toASN1Primitive();

			vec = new ASN1EncodableVector();

			//
			// signers are the last item in the sequence.
			//
			vec.add(sD.getObjectAt(0)); // version
			vec.add(digests);

			for (int i = 2; i != sD.size() - 1; i++)
			{
				vec.add(sD.getObjectAt(i));
			}

			vec.add(signers);

			cms.signedData = SignedData.getInstance(new BERSequence(vec));

			//
			// replace the contentInfo with the new one
			//
			cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);

			return cms;
		}

		/// <summary>
		/// Replace the certificate and CRL information associated with this
		/// CMSSignedData object with the new one passed in.
		/// </summary>
		/// <param name="signedData"> the signed data object to be used as a base. </param>
		/// <param name="certificates"> the new certificates to be used. </param>
		/// <param name="attrCerts"> the new attribute certificates to be used. </param>
		/// <param name="revocations"> the new CRLs to be used - a collection of X509CRLHolder objects, OtherRevocationInfoFormat, or both. </param>
		/// <returns> a new signed data object. </returns>
		/// <exception cref="CMSException"> if there is an error processing the CertStore </exception>
		public static CMSSignedData replaceCertificatesAndCRLs(CMSSignedData signedData, Store certificates, Store attrCerts, Store revocations)
		{
			//
			// copy
			//
			CMSSignedData cms = new CMSSignedData(signedData);

			//
			// replace the certs and revocations in the SignedData object
			//
			ASN1Set certSet = null;
			ASN1Set crlSet = null;

			if (certificates != null || attrCerts != null)
			{
				List certs = new ArrayList();

				if (certificates != null)
				{
					certs.addAll(CMSUtils.getCertificatesFromStore(certificates));
				}
				if (attrCerts != null)
				{
					certs.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts));
				}

				ASN1Set set = CMSUtils.createBerSetFromList(certs);

				if (set.size() != 0)
				{
					certSet = set;
				}
			}

			if (revocations != null)
			{
				ASN1Set set = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(revocations));

				if (set.size() != 0)
				{
					crlSet = set;
				}
			}

			//
			// replace the CMS structure.
			//
			cms.signedData = new SignedData(signedData.signedData.getDigestAlgorithms(), signedData.signedData.getEncapContentInfo(), certSet, crlSet, signedData.signedData.getSignerInfos());

			//
			// replace the contentInfo with the new one
			//
			cms.contentInfo = new ContentInfo(cms.contentInfo.getContentType(), cms.signedData);

			return cms;
		}
	}

}