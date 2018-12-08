using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using SignedData = org.bouncycastle.asn1.cms.SignedData;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;

	/// <summary>
	/// general class for generating a pkcs7-signature message.
	/// <para>
	/// A simple example of usage, generating a detached signature.
	/// 
	/// <pre>
	///      List             certList = new ArrayList();
	///      CMSTypedData     msg = new CMSProcessableByteArray("Hello world!".getBytes());
	/// 
	///      certList.add(signCert);
	/// 
	///      Store           certs = new JcaCertStore(certList);
	/// 
	///      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	///      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
	/// 
	///      gen.addSignerInfoGenerator(
	///                new JcaSignerInfoGeneratorBuilder(
	///                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
	///                     .build(sha1Signer, signCert));
	/// 
	///      gen.addCertificates(certs);
	/// 
	///      CMSSignedData sigData = gen.generate(msg, false);
	/// </pre>
	/// </para>
	/// </summary>
	public class CMSSignedDataGenerator : CMSSignedGenerator
	{
		private List signerInfs = new ArrayList();

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSSignedDataGenerator()
		{
		}

		/// <summary>
		/// Generate a CMS Signed Data object carrying a detached CMS signature.
		/// </summary>
		/// <param name="content"> the content to be signed. </param>
		public virtual CMSSignedData generate(CMSTypedData content)
		{
			return generate(content, false);
		}

		/// <summary>
		/// Generate a CMS Signed Data object which can be carrying a detached CMS signature, or have encapsulated data, depending on the value
		/// of the encapsulated parameter.
		/// </summary>
		/// <param name="content"> the content to be signed. </param>
		/// <param name="encapsulate"> true if the content should be encapsulated in the signature, false otherwise. </param>
		public virtual CMSSignedData generate(CMSTypedData content, bool encapsulate)
		{
			if (!signerInfs.isEmpty())
			{
				throw new IllegalStateException("this method can only be used with SignerInfoGenerator");
			}

					// TODO
	//        if (signerInfs.isEmpty())
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

			ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
			ASN1EncodableVector signerInfos = new ASN1EncodableVector();

			digests.clear(); // clear the current preserved digest state

			//
			// add the precalculated SignerInfo objects.
			//
			for (Iterator it = _signers.iterator(); it.hasNext();)
			{
				SignerInformation signer = (SignerInformation)it.next();
				digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));

				// TODO Verify the content type and calculated digest match the precalculated SignerInfo
				signerInfos.add(signer.toASN1Structure());
			}

			//
			// add the SignerInfo objects
			//
			ASN1ObjectIdentifier contentTypeOID = content.getContentType();

			ASN1OctetString octs = null;

			if (content.getContent() != null)
			{
				ByteArrayOutputStream bOut = null;

				if (encapsulate)
				{
					bOut = new ByteArrayOutputStream();
				}

				OutputStream cOut = CMSUtils.attachSignersToOutputStream(signerGens, bOut);

				// Just in case it's unencapsulated and there are no signers!
				cOut = CMSUtils.getSafeOutputStream(cOut);

				try
				{
					content.write(cOut);

					cOut.close();
				}
				catch (IOException e)
				{
					throw new CMSException("data processing exception: " + e.Message, e);
				}

				if (encapsulate)
				{
					octs = new BEROctetString(bOut.toByteArray());
				}
			}

			for (Iterator it = signerGens.iterator(); it.hasNext();)
			{
				SignerInfoGenerator sGen = (SignerInfoGenerator)it.next();
				SignerInfo inf = sGen.generate(contentTypeOID);

				digestAlgs.add(inf.getDigestAlgorithm());
				signerInfos.add(inf);

				byte[] calcDigest = sGen.getCalculatedDigest();

				if (calcDigest != null)
				{
					digests.put(inf.getDigestAlgorithm().getAlgorithm().getId(), calcDigest);
				}
			}

			ASN1Set certificates = null;

			if (certs.size() != 0)
			{
				certificates = CMSUtils.createBerSetFromList(certs);
			}

			ASN1Set certrevlist = null;

			if (crls.size() != 0)
			{
				certrevlist = CMSUtils.createBerSetFromList(crls);
			}

			ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

			SignedData sd = new SignedData(new DERSet(digestAlgs), encInfo, certificates, certrevlist, new DERSet(signerInfos));

			ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers_Fields.signedData, sd);

			return new CMSSignedData(content, contentInfo);
		}

		/// <summary>
		/// generate a set of one or more SignerInformation objects representing counter signatures on
		/// the passed in SignerInformation object.
		/// </summary>
		/// <param name="signer"> the signer to be countersigned </param>
		/// <returns> a store containing the signers. </returns>
		public virtual SignerInformationStore generateCounterSigners(SignerInformation signer)
		{
			return this.generate(new CMSProcessableByteArray(null, signer.getSignature()), false).getSignerInfos();
		}
	}


}