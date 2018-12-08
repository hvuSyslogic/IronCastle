using org.bouncycastle.asn1;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Generator = org.bouncycastle.asn1.ASN1Generator;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetStringParser = org.bouncycastle.asn1.ASN1OctetStringParser;
	using ASN1SequenceParser = org.bouncycastle.asn1.ASN1SequenceParser;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1SetParser = org.bouncycastle.asn1.ASN1SetParser;
	using ASN1StreamParser = org.bouncycastle.asn1.ASN1StreamParser;
	using BERSequenceGenerator = org.bouncycastle.asn1.BERSequenceGenerator;
	using BERSetParser = org.bouncycastle.asn1.BERSetParser;
	using BERTaggedObject = org.bouncycastle.asn1.BERTaggedObject;
	using BERTags = org.bouncycastle.asn1.BERTags;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfoParser = org.bouncycastle.asn1.cms.ContentInfoParser;
	using SignedDataParser = org.bouncycastle.asn1.cms.SignedDataParser;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Store = org.bouncycastle.util.Store;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Parsing class for an CMS Signed Data object from an input stream.
	/// <para>
	/// Note: that because we are in a streaming mode only one signer can be tried and it is important 
	/// that the methods on the parser are called in the appropriate order.
	/// </para>
	/// <para>
	/// A simple example of usage for an encapsulated signature.
	/// </para>
	/// <para>
	/// Two notes: first, in the example below the validity of
	/// the certificate isn't verified, just the fact that one of the certs 
	/// matches the given signer, and, second, because we are in a streaming
	/// mode the order of the operations is important.
	/// </para>
	/// <pre>
	///      CMSSignedDataParser     sp = new CMSSignedDataParser(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build(), encapSigData);
	/// 
	///      sp.getSignedContent().drain();
	/// 
	///      Store                   certStore = sp.getCertificates();
	///      SignerInformationStore  signers = sp.getSignerInfos();
	/// 
	///      Collection              c = signers.getSigners();
	///      Iterator                it = c.iterator();
	/// 
	///      while (it.hasNext())
	///      {
	///          SignerInformation   signer = (SignerInformation)it.next();
	///          Collection          certCollection = certStore.getMatches(signer.getSID());
	/// 
	///          Iterator        certIt = certCollection.iterator();
	///          X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
	/// 
	///          JavaSystem.@out.println("verify returns: " + signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)));
	///      }
	/// </pre>
	///  Note also: this class does not introduce buffering - if you are processing large files you should create
	///  the parser with:
	///  <pre>
	///          CMSSignedDataParser     ep = new CMSSignedDataParser(new BufferedInputStream(encapSigData, bufSize));
	///  </pre>
	///  where bufSize is a suitably large buffer size.
	/// </summary>
	public class CMSSignedDataParser : CMSContentInfoParser
	{
		private static readonly CMSSignedHelper HELPER = CMSSignedHelper.INSTANCE;

		private SignedDataParser _signedData;
		private ASN1ObjectIdentifier _signedContentType;
		private CMSTypedStream _signedContent;
		private Map digests;
		private Set<AlgorithmIdentifier> digestAlgorithms;

		private SignerInformationStore _signerInfoStore;
		private ASN1Set _certSet, _crlSet;
		private bool _isCertCrlParsed;

		public CMSSignedDataParser(DigestCalculatorProvider digestCalculatorProvider, byte[] sigBlock) : this(digestCalculatorProvider, new ByteArrayInputStream(sigBlock))
		{
		}

		public CMSSignedDataParser(DigestCalculatorProvider digestCalculatorProvider, CMSTypedStream signedContent, byte[] sigBlock) : this(digestCalculatorProvider, signedContent, new ByteArrayInputStream(sigBlock))
		{
		}

		/// <summary>
		/// base constructor - with encapsulated content
		/// </summary>
		public CMSSignedDataParser(DigestCalculatorProvider digestCalculatorProvider, InputStream sigData) : this(digestCalculatorProvider, null, sigData)
		{
		}

		/// <summary>
		/// base constructor
		/// </summary>
		/// <param name="digestCalculatorProvider"> for generating accumulating digests </param>
		/// <param name="signedContent"> the content that was signed. </param>
		/// <param name="sigData"> the signature object stream. </param>
		public CMSSignedDataParser(DigestCalculatorProvider digestCalculatorProvider, CMSTypedStream signedContent, InputStream sigData) : base(sigData)
		{

			try
			{
				_signedContent = signedContent;
				_signedData = SignedDataParser.getInstance(_contentInfo.getContent(BERTags_Fields.SEQUENCE));
				digests = new HashMap();

				ASN1SetParser digAlgs = _signedData.getDigestAlgorithms();
				ASN1Encodable o;

				Set<AlgorithmIdentifier> algSet = new HashSet<AlgorithmIdentifier>();

				while ((o = digAlgs.readObject()) != null)
				{
					AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(o);

					algSet.add(algId);

					try
					{
						DigestCalculator calculator = digestCalculatorProvider.get(algId);

						if (calculator != null)
						{
							this.digests.put(algId.getAlgorithm(), calculator);
						}
					}
					catch (OperatorCreationException)
					{
						 //  ignore
					}
				}

				digestAlgorithms = Collections.unmodifiableSet(algSet);

				//
				// If the message is simply a certificate chain message getContent() may return null.
				//
				ContentInfoParser cont = _signedData.getEncapContentInfo();
				ASN1Encodable contentParser = cont.getContent(BERTags_Fields.OCTET_STRING);

				if (contentParser is ASN1OctetStringParser)
				{
					ASN1OctetStringParser octs = (ASN1OctetStringParser)contentParser;

					CMSTypedStream ctStr = new CMSTypedStream(cont.getContentType(), octs.getOctetStream());

					if (_signedContent == null)
					{
						_signedContent = ctStr;
					}
					else
					{
						//
						// content passed in, need to read past empty encapsulated content info object if present
						//
						ctStr.drain();
					}
				}
				else if (contentParser != null)
				{
					PKCS7TypedStream pkcs7Stream = new PKCS7TypedStream(cont.getContentType(), contentParser);

					if (_signedContent == null)
					{
						_signedContent = pkcs7Stream;
					}
					else
					{
						//
						// content passed in, need to read past empty encapsulated content info object if present
						//
						pkcs7Stream.drain();
					}
				}

				if (signedContent == null)
				{
					_signedContentType = cont.getContentType();
				}
				else
				{
					_signedContentType = _signedContent.getContentType();
				}
			}
			catch (IOException e)
			{
				throw new CMSException("io exception: " + e.Message, e);
			}
		}

		/// <summary>
		/// Return the version number for the SignedData object
		/// </summary>
		/// <returns> the version number </returns>
		public virtual int getVersion()
		{
			return _signedData.getVersion().getValue().intValue();
		}

		/// <summary>
		/// Return the digest algorithm identifiers for the SignedData object
		/// </summary>
		/// <returns> the set of digest algorithm identifiers </returns>
		public virtual Set<AlgorithmIdentifier> getDigestAlgorithmIDs()
		{
			return digestAlgorithms;
		}

		/// <summary>
		/// return the collection of signers that are associated with the
		/// signatures for the message. </summary>
		/// <exception cref="CMSException">  </exception>
		public virtual SignerInformationStore getSignerInfos()
		{
			if (_signerInfoStore == null)
			{
				populateCertCrlSets();

				List signerInfos = new ArrayList();
				Map hashes = new HashMap();

				Iterator it = digests.keySet().iterator();
				while (it.hasNext())
				{
					object digestKey = it.next();

					hashes.put(digestKey, ((DigestCalculator)digests.get(digestKey)).getDigest());
				}

				try
				{
					ASN1SetParser s = _signedData.getSignerInfos();
					ASN1Encodable o;

					while ((o = s.readObject()) != null)
					{
						SignerInfo info = SignerInfo.getInstance(o.toASN1Primitive());

						byte[] hash = (byte[])hashes.get(info.getDigestAlgorithm().getAlgorithm());

						signerInfos.add(new SignerInformation(info, _signedContentType, null, hash));
					}
				}
				catch (IOException e)
				{
					throw new CMSException("io exception: " + e.Message, e);
				}

				_signerInfoStore = new SignerInformationStore(signerInfos);
			}

			return _signerInfoStore;
		}

		/// <summary>
		/// Return any X.509 certificate objects in this SignedData structure as a Store of X509CertificateHolder objects.
		/// </summary>
		/// <returns> a Store of X509CertificateHolder objects. </returns>
		public virtual Store getCertificates()
		{
			populateCertCrlSets();

			return HELPER.getCertificates(_certSet);
		}

		/// <summary>
		/// Return any X.509 CRL objects in this SignedData structure as a Store of X509CRLHolder objects.
		/// </summary>
		/// <returns> a Store of X509CRLHolder objects. </returns>
		public virtual Store getCRLs()
		{
			populateCertCrlSets();

			return HELPER.getCRLs(_crlSet);
		}

		/// <summary>
		/// Return any X.509 attribute certificate objects in this SignedData structure as a Store of X509AttributeCertificateHolder objects.
		/// </summary>
		/// <returns> a Store of X509AttributeCertificateHolder objects. </returns>
		public virtual Store getAttributeCertificates()
		{
			populateCertCrlSets();

			return HELPER.getAttributeCertificates(_certSet);
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
			populateCertCrlSets();

			return HELPER.getOtherRevocationInfo(otherRevocationInfoFormat, _crlSet);
		}

		private void populateCertCrlSets()
		{
			if (_isCertCrlParsed)
			{
				return;
			}

			_isCertCrlParsed = true;

			try
			{
				// care! Streaming - these must be done in exactly this order.
				_certSet = getASN1Set(_signedData.getCertificates());
				_crlSet = getASN1Set(_signedData.getCrls());
			}
			catch (IOException e)
			{
				throw new CMSException("problem parsing cert/crl sets", e);
			}
		}

		/// <summary>
		/// Return the a string representation of the OID associated with the
		/// encapsulated content info structure carried in the signed data.
		/// </summary>
		/// <returns> the OID for the content type. </returns>
		public virtual string getSignedContentTypeOID()
		{
			return _signedContentType.getId();
		}

		public virtual CMSTypedStream getSignedContent()
		{
			if (_signedContent == null)
			{
				return null;
			}

			InputStream digStream = CMSUtils.attachDigestsToInputStream(digests.values(), _signedContent.getContentStream());

			return new CMSTypedStream(_signedContent.getContentType(), digStream);
		}

		/// <summary>
		/// Replace the signerinformation store associated with the passed
		/// in message contained in the stream original with the new one passed in.
		/// You would probably only want to do this if you wanted to change the unsigned
		/// attributes associated with a signer, or perhaps delete one.
		/// <para>
		/// The output stream is returned unclosed.
		/// </para> </summary>
		/// <param name="original"> the signed data stream to be used as a base. </param>
		/// <param name="signerInformationStore"> the new signer information store to use. </param>
		/// <param name="out"> the stream to write the new signed data object to. </param>
		/// <returns> out. </returns>
		public static OutputStream replaceSigners(InputStream original, SignerInformationStore signerInformationStore, OutputStream @out)
		{
			ASN1StreamParser @in = new ASN1StreamParser(original);
			ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)@in.readObject());
			SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags_Fields.SEQUENCE));

			BERSequenceGenerator sGen = new BERSequenceGenerator(@out);

			sGen.addObject(CMSObjectIdentifiers_Fields.signedData);

			BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

			// version number
			sigGen.addObject(signedData.getVersion());

			// digests
			signedData.getDigestAlgorithms().toASN1Primitive(); // skip old ones

			ASN1EncodableVector digestAlgs = new ASN1EncodableVector();

			for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();
				digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
			}

			sigGen.getRawOutputStream().write((new DERSet(digestAlgs)).getEncoded());

			// encap content info
			ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

			BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

			eiGen.addObject(encapContentInfo.getContentType());

			pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

			eiGen.close();


			writeSetToGeneratorTagged(sigGen, signedData.getCertificates(), 0);
			writeSetToGeneratorTagged(sigGen, signedData.getCrls(), 1);


			ASN1EncodableVector signerInfos = new ASN1EncodableVector();
			for (Iterator it = signerInformationStore.getSigners().iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();

				signerInfos.add(signer.toASN1Structure());
			}

			sigGen.getRawOutputStream().write((new DERSet(signerInfos)).getEncoded());

			sigGen.close();

			sGen.close();

			return @out;
		}

		/// <summary>
		/// Replace the certificate and CRL information associated with this
		/// CMSSignedData object with the new one passed in.
		/// <para>
		/// The output stream is returned unclosed.
		/// </para> </summary>
		/// <param name="original"> the signed data stream to be used as a base. </param>
		/// <param name="certs"> new certificates to be used, if any. </param>
		/// <param name="crls"> new CRLs to be used, if any. </param>
		/// <param name="attrCerts"> new attribute certificates to be used, if any. </param>
		/// <param name="out"> the stream to write the new signed data object to. </param>
		/// <returns> out. </returns>
		/// <exception cref="CMSException"> if there is an error processing the CertStore </exception>
		public static OutputStream replaceCertificatesAndCRLs(InputStream original, Store certs, Store crls, Store attrCerts, OutputStream @out)
		{
			ASN1StreamParser @in = new ASN1StreamParser(original);
			ContentInfoParser contentInfo = new ContentInfoParser((ASN1SequenceParser)@in.readObject());
			SignedDataParser signedData = SignedDataParser.getInstance(contentInfo.getContent(BERTags_Fields.SEQUENCE));

			BERSequenceGenerator sGen = new BERSequenceGenerator(@out);

			sGen.addObject(CMSObjectIdentifiers_Fields.signedData);

			BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

			// version number
			sigGen.addObject(signedData.getVersion());

			// digests
			sigGen.getRawOutputStream().write(signedData.getDigestAlgorithms().toASN1Primitive().getEncoded());

			// encap content info
			ContentInfoParser encapContentInfo = signedData.getEncapContentInfo();

			BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());

			eiGen.addObject(encapContentInfo.getContentType());

			pipeEncapsulatedOctetString(encapContentInfo, eiGen.getRawOutputStream());

			eiGen.close();

			//
			// skip existing certs and CRLs
			//
			getASN1Set(signedData.getCertificates());
			getASN1Set(signedData.getCrls());

			//
			// replace the certs and crls in the SignedData object
			//
			if (certs != null || attrCerts != null)
			{
				List certificates = new ArrayList();

				if (certs != null)
				{
					certificates.addAll(CMSUtils.getCertificatesFromStore(certs));
				}
				if (attrCerts != null)
				{
					certificates.addAll(CMSUtils.getAttributeCertificatesFromStore(attrCerts));
				}

				ASN1Set asn1Certs = CMSUtils.createBerSetFromList(certificates);

				if (asn1Certs.size() > 0)
				{
					sigGen.getRawOutputStream().write((new DERTaggedObject(false, 0, asn1Certs)).getEncoded());
				}
			}

			if (crls != null)
			{
				ASN1Set asn1Crls = CMSUtils.createBerSetFromList(CMSUtils.getCRLsFromStore(crls));

				if (asn1Crls.size() > 0)
				{
					sigGen.getRawOutputStream().write((new DERTaggedObject(false, 1, asn1Crls)).getEncoded());
				}
			}

			sigGen.getRawOutputStream().write(signedData.getSignerInfos().toASN1Primitive().getEncoded());

			sigGen.close();

			sGen.close();

			return @out;
		}

		private static void writeSetToGeneratorTagged(ASN1Generator asn1Gen, ASN1SetParser asn1SetParser, int tagNo)
		{
			ASN1Set asn1Set = getASN1Set(asn1SetParser);

			if (asn1Set != null)
			{
				if (asn1SetParser is BERSetParser)
				{
					asn1Gen.getRawOutputStream().write((new BERTaggedObject(false, tagNo, asn1Set)).getEncoded());
				}
				else
				{
					asn1Gen.getRawOutputStream().write((new DERTaggedObject(false, tagNo, asn1Set)).getEncoded());
				}
			}
		}

		private static ASN1Set getASN1Set(ASN1SetParser asn1SetParser)
		{
			return asn1SetParser == null ? null : ASN1Set.getInstance(asn1SetParser.toASN1Primitive());
		}

		private static void pipeEncapsulatedOctetString(ContentInfoParser encapContentInfo, OutputStream rawOutputStream)
		{
			ASN1OctetStringParser octs = (ASN1OctetStringParser) encapContentInfo.getContent(BERTags_Fields.OCTET_STRING);

			if (octs != null)
			{
				pipeOctetString(octs, rawOutputStream);
			}

	//        BERTaggedObjectParser contentObject = (BERTaggedObjectParser)encapContentInfo.getContentObject();
	//        if (contentObject != null)
	//        {
	//            // Handle IndefiniteLengthInputStream safely
	//            InputStream input = ASN1StreamParser.getSafeRawInputStream(contentObject.getContentStream(true));
	//
	//            // TODO BerTaggedObjectGenerator?
	//            BEROutputStream berOut = new BEROutputStream(rawOutputStream);
	//            berOut.write(DERTags.CONSTRUCTED | DERTags.TAGGED | 0);
	//            berOut.write(0x80);
	//
	//            pipeRawOctetString(input, rawOutputStream);
	//
	//            berOut.write(0x00);
	//            berOut.write(0x00);
	//
	//            input.close();
	//        }
		}

		private static void pipeOctetString(ASN1OctetStringParser octs, OutputStream output)
		{
			// TODO Allow specification of a specific fragment size?
			OutputStream outOctets = CMSUtils.createBEROctetOutputStream(output, 0, true, 0);
			Streams.pipeAll(octs.getOctetStream(), outOctets);
			outOctets.close();
		}

	//    private static void pipeRawOctetString(
	//        InputStream     rawInput,
	//        OutputStream    rawOutput)
	//        throws IOException
	//    {
	//        InputStream tee = new TeeInputStream(rawInput, rawOutput);
	//        ASN1StreamParser sp = new ASN1StreamParser(tee);
	//        ASN1OctetStringParser octs = (ASN1OctetStringParser)sp.readObject();
	//        Streams.drain(octs.getOctetStream());
	//    }
	}

}