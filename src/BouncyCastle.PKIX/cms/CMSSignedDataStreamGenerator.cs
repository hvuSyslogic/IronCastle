using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using BERSequenceGenerator = org.bouncycastle.asn1.BERSequenceGenerator;
	using BERTaggedObject = org.bouncycastle.asn1.BERTaggedObject;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General class for generating a pkcs7-signature message stream.
	/// <para>
	/// A simple example of usage.
	/// </para>
	/// <pre>
	///      X509Certificate signCert = ...
	///      certList.add(signCert);
	/// 
	///      Store           certs = new JcaCertStore(certList);
	///      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
	/// 
	///      CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
	/// 
	///      gen.addSignerInfoGenerator(
	///                new JcaSignerInfoGeneratorBuilder(
	///                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
	///                     .build(sha1Signer, signCert));
	/// 
	///      gen.addCertificates(certs);
	/// 
	///      OutputStream sigOut = gen.open(bOut);
	/// 
	///      sigOut.write("Hello World!".getBytes());
	/// 
	///      sigOut.close();
	/// </pre>
	/// </summary>
	public class CMSSignedDataStreamGenerator : CMSSignedGenerator
	{
		private int _bufferSize;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSSignedDataStreamGenerator()
		{
		}

		/// <summary>
		/// Set the underlying string size for encapsulated data
		/// </summary>
		/// <param name="bufferSize"> length of octet strings to buffer the data. </param>
		public virtual void setBufferSize(int bufferSize)
		{
			_bufferSize = bufferSize;
		}

		/// <summary>
		/// generate a signed object that for a CMS Signed Data
		/// object using the given provider.
		/// </summary>
		public virtual OutputStream open(OutputStream @out)
		{
			return open(@out, false);
		}

		/// <summary>
		/// generate a signed object that for a CMS Signed Data
		/// object using the given provider - if encapsulate is true a copy
		/// of the message will be included in the signature with the
		/// default content type "data".
		/// </summary>
		public virtual OutputStream open(OutputStream @out, bool encapsulate)
		{
			return open(CMSObjectIdentifiers_Fields.data, @out, encapsulate);
		}

		/// <summary>
		/// generate a signed object that for a CMS Signed Data
		/// object using the given provider - if encapsulate is true a copy
		/// of the message will be included in the signature with the
		/// default content type "data". If dataOutputStream is non null the data
		/// being signed will be written to the stream as it is processed. </summary>
		/// <param name="out"> stream the CMS object is to be written to. </param>
		/// <param name="encapsulate"> true if data should be encapsulated. </param>
		/// <param name="dataOutputStream"> output stream to copy the data being signed to. </param>
		public virtual OutputStream open(OutputStream @out, bool encapsulate, OutputStream dataOutputStream)
		{
			return open(CMSObjectIdentifiers_Fields.data, @out, encapsulate, dataOutputStream);
		}

		/// <summary>
		/// generate a signed object that for a CMS Signed Data
		/// object using the given provider - if encapsulate is true a copy
		/// of the message will be included in the signature. The content type
		/// is set according to the OID represented by the string signedContentType.
		/// </summary>
		public virtual OutputStream open(ASN1ObjectIdentifier eContentType, OutputStream @out, bool encapsulate)
		{
			return open(eContentType, @out, encapsulate, null);
		}

		/// <summary>
		/// generate a signed object that for a CMS Signed Data
		/// object using the given provider - if encapsulate is true a copy
		/// of the message will be included in the signature. The content type
		/// is set according to the OID represented by the string signedContentType. </summary>
		/// <param name="eContentType"> OID for data to be signed. </param>
		/// <param name="out"> stream the CMS object is to be written to. </param>
		/// <param name="encapsulate"> true if data should be encapsulated. </param>
		/// <param name="dataOutputStream"> output stream to copy the data being signed to. </param>
		public virtual OutputStream open(ASN1ObjectIdentifier eContentType, OutputStream @out, bool encapsulate, OutputStream dataOutputStream)
		{
			// TODO
	//        if (_signerInfs.isEmpty())
	//        {
	//            /* RFC 3852 5.2
	//             * "In the degenerate case where there are no signers, the
	//             * EncapsulatedContentInfo value being "signed" is irrelevant.  In this
	//             * case, the content type within the EncapsulatedContentInfo value being
	//             * "signed" MUST be id-data (as defined in section 4), and the content
	//             * field of the EncapsulatedContentInfo value MUST be omitted."
	//             */
	//            if (encapsulate)
	//            {
	//                throw new IllegalArgumentException("no signers, encapsulate must be false");
	//            }
	//            if (!DATA.equals(eContentType))
	//            {
	//                throw new IllegalArgumentException("no signers, eContentType must be id-data");
	//            }
	//        }
	//
	//        if (!DATA.equals(eContentType))
	//        {
	//            /* RFC 3852 5.3
	//             * [The 'signedAttrs']...
	//             * field is optional, but it MUST be present if the content type of
	//             * the EncapsulatedContentInfo value being signed is not id-data.
	//             */
	//            // TODO signedAttrs must be present for all signers
	//        }

			//
			// ContentInfo
			//
			BERSequenceGenerator sGen = new BERSequenceGenerator(@out);

			sGen.addObject(CMSObjectIdentifiers_Fields.signedData);

			//
			// Signed Data
			//
			BERSequenceGenerator sigGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

			sigGen.addObject(calculateVersion(eContentType));

			ASN1EncodableVector digestAlgs = new ASN1EncodableVector();

			//
			// add the precalculated SignerInfo digest algorithms.
			//
			for (Iterator it = _signers.iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();
				AlgorithmIdentifier digAlg = CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID());

				digestAlgs.add(digAlg);
			}

			//
			// add the new digests
			//

			for (Iterator it = signerGens.iterator(); it.hasNext();)
			{
				SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();

				digestAlgs.add(signerGen.getDigestAlgorithm());
			}

			sigGen.getRawOutputStream().write((new DERSet(digestAlgs)).getEncoded());

			BERSequenceGenerator eiGen = new BERSequenceGenerator(sigGen.getRawOutputStream());
			eiGen.addObject(eContentType);

			// If encapsulating, add the data as an octet string in the sequence
			OutputStream encapStream = encapsulate ? CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, true, _bufferSize) : null;

			// Also send the data to 'dataOutputStream' if necessary
			OutputStream contentStream = CMSUtils.getSafeTeeOutputStream(dataOutputStream, encapStream);

			// Let all the signers see the data as it is written
			OutputStream sigStream = CMSUtils.attachSignersToOutputStream(signerGens, contentStream);

			return new CmsSignedDataOutputStream(this, sigStream, eContentType, sGen, sigGen, eiGen);
		}

		/// <summary>
		/// Return a list of the current Digest AlgorithmIdentifiers applying to the next signature.
		/// </summary>
		/// <returns> a list of the Digest AlgorithmIdentifiers </returns>
		public virtual List<AlgorithmIdentifier> getDigestAlgorithms()
		{
			List digestAlorithms = new ArrayList();

			//
			// add the precalculated SignerInfo digest algorithms.
			//
			for (Iterator it = _signers.iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();
				AlgorithmIdentifier digAlg = CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID());

				digestAlorithms.add(digAlg);
			}

			//
			// add the new digests
			//

			for (Iterator it = signerGens.iterator(); it.hasNext();)
			{
				SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();

				digestAlorithms.add(signerGen.getDigestAlgorithm());
			}

		   return digestAlorithms;
		}

		// RFC3852, section 5.1:
		// IF ((certificates is present) AND
		//    (any certificates with a type of other are present)) OR
		//    ((crls is present) AND
		//    (any crls with a type of other are present))
		// THEN version MUST be 5
		// ELSE
		//    IF (certificates is present) AND
		//       (any version 2 attribute certificates are present)
		//    THEN version MUST be 4
		//    ELSE
		//       IF ((certificates is present) AND
		//          (any version 1 attribute certificates are present)) OR
		//          (any SignerInfo structures are version 3) OR
		//          (encapContentInfo eContentType is other than id-data)
		//       THEN version MUST be 3
		//       ELSE version MUST be 1
		//
		private ASN1Integer calculateVersion(ASN1ObjectIdentifier contentOid)
		{
			bool otherCert = false;
			bool otherCrl = false;
			bool attrCertV1Found = false;
			bool attrCertV2Found = false;

			if (certs != null)
			{
				for (Iterator it = certs.iterator(); it.hasNext();)
				{
					object obj = it.next();
					if (obj is ASN1TaggedObject)
					{
						ASN1TaggedObject tagged = (ASN1TaggedObject)obj;

						if (tagged.getTagNo() == 1)
						{
							attrCertV1Found = true;
						}
						else if (tagged.getTagNo() == 2)
						{
							attrCertV2Found = true;
						}
						else if (tagged.getTagNo() == 3)
						{
							otherCert = true;
						}
					}
				}
			}

			if (otherCert)
			{
				return new ASN1Integer(5);
			}

			if (crls != null) // no need to check if otherCert is true
			{
				for (Iterator it = crls.iterator(); it.hasNext();)
				{
					object obj = it.next();
					if (obj is ASN1TaggedObject)
					{
						otherCrl = true;
					}
				}
			}

			if (otherCrl)
			{
				return new ASN1Integer(5);
			}

			if (attrCertV2Found)
			{
				return new ASN1Integer(4);
			}

			if (attrCertV1Found)
			{
				return new ASN1Integer(3);
			}

			if (checkForVersion3(_signers, signerGens))
			{
				return new ASN1Integer(3);
			}

			if (!CMSObjectIdentifiers_Fields.data.Equals(contentOid))
			{
				return new ASN1Integer(3);
			}

			return new ASN1Integer(1);
		}

		private bool checkForVersion3(List signerInfos, List signerInfoGens)
		{
			for (Iterator it = signerInfos.iterator(); it.hasNext();)
			{
				SignerInfo s = SignerInfo.getInstance(((SignerInformation)it.next()).toASN1Structure());

				if (s.getVersion().getValue().intValue() == 3)
				{
					return true;
				}
			}

			for (Iterator it = signerInfoGens.iterator(); it.hasNext();)
			{
				SignerInfoGenerator s = (SignerInfoGenerator)it.next();

				if (s.getGeneratedVersion() == 3)
				{
					return true;
				}
			}

			return false;
		}

		public class CmsSignedDataOutputStream : OutputStream
		{
			private readonly CMSSignedDataStreamGenerator outerInstance;

			internal OutputStream _out;
			internal ASN1ObjectIdentifier _contentOID;
			internal BERSequenceGenerator _sGen;
			internal BERSequenceGenerator _sigGen;
			internal BERSequenceGenerator _eiGen;

			public CmsSignedDataOutputStream(CMSSignedDataStreamGenerator outerInstance, OutputStream @out, ASN1ObjectIdentifier contentOID, BERSequenceGenerator sGen, BERSequenceGenerator sigGen, BERSequenceGenerator eiGen)
			{
				this.outerInstance = outerInstance;
				_out = @out;
				_contentOID = contentOID;
				_sGen = sGen;
				_sigGen = sigGen;
				_eiGen = eiGen;
			}

			public virtual void write(int b)
			{
				_out.write(b);
			}

			public virtual void write(byte[] bytes, int off, int len)
			{
				_out.write(bytes, off, len);
			}

			public virtual void write(byte[] bytes)
			{
				_out.write(bytes);
			}

			public virtual void close()
			{
				_out.close();
				_eiGen.close();

				outerInstance.digests.clear(); // clear the current preserved digest state

				if (outerInstance.certs.size() != 0)
				{
					ASN1Set certSet = CMSUtils.createBerSetFromList(outerInstance.certs);

					_sigGen.getRawOutputStream().write((new BERTaggedObject(false, 0, certSet)).getEncoded());
				}

				if (outerInstance.crls.size() != 0)
				{
					ASN1Set crlSet = CMSUtils.createBerSetFromList(outerInstance.crls);

					_sigGen.getRawOutputStream().write((new BERTaggedObject(false, 1, crlSet)).getEncoded());
				}

				//
				// collect all the SignerInfo objects
				//
				ASN1EncodableVector signerInfos = new ASN1EncodableVector();

				//
				// add the generated SignerInfo objects
				//

				for (Iterator it = outerInstance.signerGens.iterator(); it.hasNext();)
				{
					SignerInfoGenerator sigGen = (SignerInfoGenerator)it.next();


					try
					{
						signerInfos.add(sigGen.generate(_contentOID));

						byte[] calculatedDigest = sigGen.getCalculatedDigest();

						outerInstance.digests.put(sigGen.getDigestAlgorithm().getAlgorithm().getId(), calculatedDigest);
					}
					catch (CMSException e)
					{
						throw new CMSStreamException("exception generating signers: " + e.Message, e);
					}
				}

				//
				// add the precalculated SignerInfo objects
				//
				{
					Iterator it = outerInstance._signers.iterator();
					while (it.hasNext())
					{
						SignerInformation signer = (SignerInformation)it.next();

						// TODO Verify the content type and calculated digest match the precalculated SignerInfo
	//                    if (!signer.getContentType().equals(_contentOID))
	//                    {
	//                        // TODO The precalculated content type did not match - error?
	//                    }
	//                    
	//                    byte[] calculatedDigest = (byte[])_digests.get(signer.getDigestAlgOID());
	//                    if (calculatedDigest == null)
	//                    {
	//                        // TODO We can't confirm this digest because we didn't calculate it - error?
	//                    }
	//                    else
	//                    {
	//                        if (!Arrays.areEqual(signer.getContentDigest(), calculatedDigest))
	//                        {
	//                            // TODO The precalculated digest did not match - error?
	//                        }
	//                    }

						signerInfos.add(signer.toASN1Structure());
					}
				}

				_sigGen.getRawOutputStream().write((new DERSet(signerInfos)).getEncoded());

				_sigGen.close();
				_sGen.close();
			}
		}
	}

}