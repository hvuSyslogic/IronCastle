using org.bouncycastle.asn1;
using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BEROctetString = org.bouncycastle.asn1.BEROctetString;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AuthenticatedData = org.bouncycastle.asn1.cms.AuthenticatedData;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	/// <summary>
	/// General class for generating a CMS authenticated-data message.
	/// 
	/// A simple example of usage.
	/// 
	/// <pre>
	///      CMSAuthenticatedDataGenerator  fact = new CMSAuthenticatedDataGenerator();
	/// 
	///      adGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
	/// 
	///      CMSAuthenticatedData         data = fact.generate(new CMSProcessableByteArray(data),
	///                              new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider(BC).build()));
	/// </pre>
	/// </summary>
	public class CMSAuthenticatedDataGenerator : CMSAuthenticatedGenerator
	{
		/// <summary>
		/// base constructor
		/// </summary>
		public CMSAuthenticatedDataGenerator()
		{
		}

		/// <summary>
		/// Generate an authenticated data object from the passed in typedData and MacCalculator.
		/// </summary>
		/// <param name="typedData"> the data to have a MAC attached. </param>
		/// <param name="macCalculator"> the calculator of the MAC to be attached. </param>
		/// <returns> the resulting CMSAuthenticatedData object. </returns>
		/// <exception cref="CMSException"> on failure in encoding data or processing recipients. </exception>
		public virtual CMSAuthenticatedData generate(CMSTypedData typedData, MacCalculator macCalculator)
		{
			return generate(typedData, macCalculator, null);
		}

		/// <summary>
		/// Generate an authenticated data object from the passed in typedData and MacCalculator.
		/// </summary>
		/// <param name="typedData"> the data to have a MAC attached. </param>
		/// <param name="macCalculator"> the calculator of the MAC to be attached. </param>
		/// <param name="digestCalculator"> calculator for computing digest of the encapsulated data. </param>
		/// <returns> the resulting CMSAuthenticatedData object. </returns>
		/// <exception cref="CMSException"> on failure in encoding data or processing recipients.     </exception>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public CMSAuthenticatedData generate(CMSTypedData typedData, org.bouncycastle.operator.MacCalculator macCalculator, final org.bouncycastle.operator.DigestCalculator digestCalculator) throws CMSException
		public virtual CMSAuthenticatedData generate(CMSTypedData typedData, MacCalculator macCalculator, DigestCalculator digestCalculator)
		{
			ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
			ASN1OctetString encContent;
			ASN1OctetString macResult;

			for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
			{
				RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

				recipientInfos.add(recipient.generate(macCalculator.getKey()));
			}

			AuthenticatedData authData;

			if (digestCalculator != null)
			{
				try
				{
					ByteArrayOutputStream bOut = new ByteArrayOutputStream();
					OutputStream @out = new TeeOutputStream(digestCalculator.getOutputStream(), bOut);

					typedData.write(@out);

					@out.close();

					encContent = new BEROctetString(bOut.toByteArray());
				}
				catch (IOException e)
				{
					throw new CMSException("unable to perform digest calculation: " + e.Message, e);
				}

				Map parameters = getBaseParameters(typedData.getContentType(), digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(), digestCalculator.getDigest());

				if (authGen == null)
				{
					authGen = new DefaultAuthenticatedAttributeTableGenerator();
				}
				ASN1Set authed = new DERSet(authGen.getAttributes(Collections.unmodifiableMap(parameters)).toASN1EncodableVector());

				try
				{
					OutputStream mOut = macCalculator.getOutputStream();

					mOut.write(authed.getEncoded(ASN1Encoding_Fields.DER));

					mOut.close();

					macResult = new DEROctetString(macCalculator.getMac());
				}
				catch (IOException e)
				{
					throw new CMSException("exception decoding algorithm parameters.", e);
				}
				ASN1Set unauthed = (unauthGen != null) ? new BERSet(unauthGen.getAttributes(Collections.unmodifiableMap(parameters)).toASN1EncodableVector()) : null;

				ContentInfo eci = new ContentInfo(CMSObjectIdentifiers_Fields.data, encContent);

				authData = new AuthenticatedData(originatorInfo, new DERSet(recipientInfos), macCalculator.getAlgorithmIdentifier(), digestCalculator.getAlgorithmIdentifier(), eci, authed, macResult, unauthed);
			}
			else
			{
				try
				{
					ByteArrayOutputStream bOut = new ByteArrayOutputStream();
					OutputStream mOut = new TeeOutputStream(bOut, macCalculator.getOutputStream());

					typedData.write(mOut);

					mOut.close();

					encContent = new BEROctetString(bOut.toByteArray());

					macResult = new DEROctetString(macCalculator.getMac());
				}
				catch (IOException e)
				{
					throw new CMSException("exception decoding algorithm parameters.", e);
				}

				ASN1Set unauthed = (unauthGen != null) ? new BERSet(unauthGen.getAttributes(new HashMap()).toASN1EncodableVector()) : null;

				ContentInfo eci = new ContentInfo(CMSObjectIdentifiers_Fields.data, encContent);

				authData = new AuthenticatedData(originatorInfo, new DERSet(recipientInfos), macCalculator.getAlgorithmIdentifier(), null, eci, null, macResult, unauthed);
			}

			ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers_Fields.authenticatedData, authData);

			return new CMSAuthenticatedData(contentInfo, new DigestCalculatorProviderAnonymousInnerClass(this, digestCalculator));
		}

		public class DigestCalculatorProviderAnonymousInnerClass : DigestCalculatorProvider
		{
			private readonly CMSAuthenticatedDataGenerator outerInstance;

			private DigestCalculator digestCalculator;

			public DigestCalculatorProviderAnonymousInnerClass(CMSAuthenticatedDataGenerator outerInstance, DigestCalculator digestCalculator)
			{
				this.outerInstance = outerInstance;
				this.digestCalculator = digestCalculator;
			}

			public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
			{
				return digestCalculator;
			}
		}
	}
}