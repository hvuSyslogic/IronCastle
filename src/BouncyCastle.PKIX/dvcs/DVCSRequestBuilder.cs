using org.bouncycastle.asn1.dvcs;

namespace org.bouncycastle.dvcs
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using DVCSObjectIdentifiers = org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
	using DVCSRequestInformationBuilder = org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using CMSSignedDataGenerator = org.bouncycastle.cms.CMSSignedDataGenerator;

	/// <summary>
	/// Common base class for client DVCRequest builders.
	/// This class aims at DVCSRequestInformation and TransactionIdentifier construction,
	/// and its subclasses - for Data field construction (as it is specific for the requested service).
	/// </summary>
	public abstract class DVCSRequestBuilder
	{
		private readonly ExtensionsGenerator extGenerator = new ExtensionsGenerator();
		private readonly CMSSignedDataGenerator signedDataGen = new CMSSignedDataGenerator();

		protected internal readonly DVCSRequestInformationBuilder requestInformationBuilder;

		public DVCSRequestBuilder(DVCSRequestInformationBuilder requestInformationBuilder)
		{
			this.requestInformationBuilder = requestInformationBuilder;
		}

		/// <summary>
		/// Set a nonce for this request,
		/// </summary>
		/// <param name="nonce"> </param>
		public virtual void setNonce(BigInteger nonce)
		{
			requestInformationBuilder.setNonce(nonce);
		}

		/// <summary>
		/// Set requester name.
		/// </summary>
		/// <param name="requester"> </param>
		public virtual void setRequester(GeneralName requester)
		{
			requestInformationBuilder.setRequester(requester);
		}

		/// <summary>
		/// Set DVCS name to generated requests.
		/// </summary>
		/// <param name="dvcs"> </param>
		public virtual void setDVCS(GeneralName dvcs)
		{
			requestInformationBuilder.setDVCS(dvcs);
		}

		/// <summary>
		/// Set DVCS name to generated requests.
		/// </summary>
		/// <param name="dvcs"> </param>
		public virtual void setDVCS(GeneralNames dvcs)
		{
			requestInformationBuilder.setDVCS(dvcs);
		}

		/// <summary>
		/// Set data location to generated requests.
		/// </summary>
		/// <param name="dataLocation"> </param>
		public virtual void setDataLocations(GeneralName dataLocation)
		{
			requestInformationBuilder.setDataLocations(dataLocation);
		}

		/// <summary>
		/// Set data location to generated requests.
		/// </summary>
		/// <param name="dataLocations"> </param>
		public virtual void setDataLocations(GeneralNames dataLocations)
		{
			requestInformationBuilder.setDataLocations(dataLocations);
		}

		/// <summary>
		/// Add a given extension field.
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="value"> the ASN.1 structure that forms the extension's value. </param>
		/// <exception cref="DVCSException"> if there is an issue encoding the extension for adding. </exception>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			try
			{
				extGenerator.addExtension(oid, isCritical, value);
			}
			catch (IOException e)
			{
				throw new DVCSException("cannot encode extension: " + e.Message, e);
			}
		}

		public virtual DVCSRequest createDVCRequest(Data data)
		{
			if (!extGenerator.isEmpty())
			{
				requestInformationBuilder.setExtensions(extGenerator.generate());
			}

			DVCSRequest request = new DVCSRequest(requestInformationBuilder.build(), data);

			return new DVCSRequest(new ContentInfo(DVCSObjectIdentifiers_Fields.id_ct_DVCSRequestData, request));
		}
	}

}