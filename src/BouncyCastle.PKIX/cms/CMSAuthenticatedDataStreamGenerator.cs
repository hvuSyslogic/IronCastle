using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BERSequenceGenerator = org.bouncycastle.asn1.BERSequenceGenerator;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using AuthenticatedData = org.bouncycastle.asn1.cms.AuthenticatedData;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	/// <summary>
	/// General class for generating a CMS authenticated-data message stream.
	/// <para>
	/// A simple example of usage.
	/// <pre>
	///      CMSAuthenticatedDataStreamGenerator edGen = new CMSAuthenticatedDataStreamGenerator();
	/// 
	///      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider("BC"));
	/// 
	///      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
	/// 
	///      OutputStream out = edGen.open(
	///                              bOut, new JceCMSMacCalculatorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build());*
	///      out.write(data);
	/// 
	///      out.close();
	/// </pre>
	/// </para>
	/// </summary>
	public class CMSAuthenticatedDataStreamGenerator : CMSAuthenticatedGenerator
	{
		// Currently not handled
	//    private Object              _originatorInfo = null;
	//    private Object              _unprotectedAttributes = null;
		private int bufferSize;
		private bool berEncodeRecipientSet;
		private MacCalculator macCalculator;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSAuthenticatedDataStreamGenerator()
		{
		}

		/// <summary>
		/// Set the underlying string size for encapsulated data
		/// </summary>
		/// <param name="bufferSize"> length of octet strings to buffer the data. </param>
		public virtual void setBufferSize(int bufferSize)
		{
			this.bufferSize = bufferSize;
		}

		/// <summary>
		/// Use a BER Set to store the recipient information. By default recipients are
		/// stored in a DER encoding.
		/// </summary>
		/// <param name="useBerEncodingForRecipients"> true if a BER set should be used, false if DER. </param>
		public virtual void setBEREncodeRecipients(bool useBerEncodingForRecipients)
		{
			berEncodeRecipientSet = useBerEncodingForRecipients;
		}

		/// <summary>
		/// generate an authenticated data structure with the encapsulated bytes marked as DATA.
		/// </summary>
		/// <param name="out"> the stream to store the authenticated structure in. </param>
		/// <param name="macCalculator"> calculator for the MAC to be attached to the data. </param>
		public virtual OutputStream open(OutputStream @out, MacCalculator macCalculator)
		{
			return open(CMSObjectIdentifiers_Fields.data, @out, macCalculator);
		}

		public virtual OutputStream open(OutputStream @out, MacCalculator macCalculator, DigestCalculator digestCalculator)
		{
			return open(CMSObjectIdentifiers_Fields.data, @out, macCalculator, digestCalculator);
		}

		/// <summary>
		/// generate an authenticated data structure with the encapsulated bytes marked as type dataType.
		/// </summary>
		/// <param name="dataType"> the type of the data been written to the object. </param>
		/// <param name="out"> the stream to store the authenticated structure in. </param>
		/// <param name="macCalculator"> calculator for the MAC to be attached to the data. </param>
		public virtual OutputStream open(ASN1ObjectIdentifier dataType, OutputStream @out, MacCalculator macCalculator)
		{
			return open(dataType, @out, macCalculator, null);
		}

		/// <summary>
		/// generate an authenticated data structure with the encapsulated bytes marked as type dataType.
		/// </summary>
		/// <param name="dataType"> the type of the data been written to the object. </param>
		/// <param name="out"> the stream to store the authenticated structure in. </param>
		/// <param name="macCalculator"> calculator for the MAC to be attached to the data. </param>
		/// <param name="digestCalculator"> calculator for computing digest of the encapsulated data. </param>
		public virtual OutputStream open(ASN1ObjectIdentifier dataType, OutputStream @out, MacCalculator macCalculator, DigestCalculator digestCalculator)
		{
			this.macCalculator = macCalculator;

			try
			{
				ASN1EncodableVector recipientInfos = new ASN1EncodableVector();

				for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
				{
					RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

					recipientInfos.add(recipient.generate(macCalculator.getKey()));
				}

				//
				// ContentInfo
				//
				BERSequenceGenerator cGen = new BERSequenceGenerator(@out);

				cGen.addObject(CMSObjectIdentifiers_Fields.authenticatedData);

				//
				// Authenticated Data
				//
				BERSequenceGenerator authGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

				authGen.addObject(new ASN1Integer(AuthenticatedData.calculateVersion(originatorInfo)));

				if (originatorInfo != null)
				{
					authGen.addObject(new DERTaggedObject(false, 0, originatorInfo));
				}

				if (berEncodeRecipientSet)
				{
					authGen.getRawOutputStream().write((new BERSet(recipientInfos)).getEncoded());
				}
				else
				{
					authGen.getRawOutputStream().write((new DERSet(recipientInfos)).getEncoded());
				}

				AlgorithmIdentifier macAlgId = macCalculator.getAlgorithmIdentifier();

				authGen.getRawOutputStream().write(macAlgId.getEncoded());

				if (digestCalculator != null)
				{
					authGen.addObject(new DERTaggedObject(false, 1, digestCalculator.getAlgorithmIdentifier()));
				}

				BERSequenceGenerator eiGen = new BERSequenceGenerator(authGen.getRawOutputStream());

				eiGen.addObject(dataType);

				OutputStream octetStream = CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, false, bufferSize);

				OutputStream mOut;

				if (digestCalculator != null)
				{
					mOut = new TeeOutputStream(octetStream, digestCalculator.getOutputStream());
				}
				else
				{
					mOut = new TeeOutputStream(octetStream, macCalculator.getOutputStream());
				}

				return new CmsAuthenticatedDataOutputStream(this, macCalculator, digestCalculator, dataType, mOut, cGen, authGen, eiGen);
			}
			catch (IOException e)
			{
				throw new CMSException("exception decoding algorithm parameters.", e);
			}
		}

		public class CmsAuthenticatedDataOutputStream : OutputStream
		{
			private readonly CMSAuthenticatedDataStreamGenerator outerInstance;

			internal OutputStream dataStream;
			internal BERSequenceGenerator cGen;
			internal BERSequenceGenerator envGen;
			internal BERSequenceGenerator eiGen;
			internal MacCalculator macCalculator;
			internal DigestCalculator digestCalculator;
			internal ASN1ObjectIdentifier contentType;

			public CmsAuthenticatedDataOutputStream(CMSAuthenticatedDataStreamGenerator outerInstance, MacCalculator macCalculator, DigestCalculator digestCalculator, ASN1ObjectIdentifier contentType, OutputStream dataStream, BERSequenceGenerator cGen, BERSequenceGenerator envGen, BERSequenceGenerator eiGen)
			{
				this.outerInstance = outerInstance;
				this.macCalculator = macCalculator;
				this.digestCalculator = digestCalculator;
				this.contentType = contentType;
				this.dataStream = dataStream;
				this.cGen = cGen;
				this.envGen = envGen;
				this.eiGen = eiGen;
			}

			public virtual void write(int b)
			{
				dataStream.write(b);
			}

			public virtual void write(byte[] bytes, int off, int len)
			{
				dataStream.write(bytes, off, len);
			}

			public virtual void write(byte[] bytes)
			{
				dataStream.write(bytes);
			}

			public virtual void close()
			{
				dataStream.close();
				eiGen.close();

				Map parameters;

				if (digestCalculator != null)
				{
					parameters = Collections.unmodifiableMap(outerInstance.getBaseParameters(contentType, digestCalculator.getAlgorithmIdentifier(), macCalculator.getAlgorithmIdentifier(), digestCalculator.getDigest()));

					if (outerInstance.authGen == null)
					{
						outerInstance.authGen = new DefaultAuthenticatedAttributeTableGenerator();
					}

					ASN1Set authed = new DERSet(outerInstance.authGen.getAttributes(parameters).toASN1EncodableVector());

					OutputStream mOut = macCalculator.getOutputStream();

					mOut.write(authed.getEncoded(ASN1Encoding_Fields.DER));

					mOut.close();

					envGen.addObject(new DERTaggedObject(false, 2, authed));
				}
				else
				{
					parameters = Collections.unmodifiableMap(new HashMap());
				}

				envGen.addObject(new DEROctetString(macCalculator.getMac()));

				if (outerInstance.unauthGen != null)
				{
					envGen.addObject(new DERTaggedObject(false, 3, new BERSet(outerInstance.unauthGen.getAttributes(parameters).toASN1EncodableVector())));
				}

				envGen.close();
				cGen.close();
			}
		}
	}
}