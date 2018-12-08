using org.bouncycastle.asn1.cms;

namespace org.bouncycastle.cms
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using BERSequenceGenerator = org.bouncycastle.asn1.BERSequenceGenerator;
	using BERSet = org.bouncycastle.asn1.BERSet;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSObjectIdentifiers = org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	/// <summary>
	/// General class for generating a CMS enveloped-data message stream.
	/// <para>
	/// A simple example of usage.
	/// <pre>
	///      CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
	/// 
	///      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
	/// 
	///      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
	/// 
	///      OutputStream out = edGen.open(
	///                              bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
	///                                              .setProvider("BC").build());
	///      out.write(data);
	/// 
	///      out.close();
	/// </pre>
	/// </para>
	/// </summary>
	public class CMSEnvelopedDataStreamGenerator : CMSEnvelopedGenerator
	{
		private ASN1Set _unprotectedAttributes = null;
		private int _bufferSize;
		private bool _berEncodeRecipientSet;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSEnvelopedDataStreamGenerator()
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
		/// Use a BER Set to store the recipient information
		/// </summary>
		public virtual void setBEREncodeRecipients(bool berEncodeRecipientSet)
		{
			_berEncodeRecipientSet = berEncodeRecipientSet;
		}

		private ASN1Integer getVersion()
		{
			if (originatorInfo != null || _unprotectedAttributes != null)
			{
				return new ASN1Integer(2);
			}
			else
			{
				return new ASN1Integer(0);
			}
		}

		private OutputStream doOpen(ASN1ObjectIdentifier dataType, OutputStream @out, OutputEncryptor encryptor)
		{
			ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
			GenericKey encKey = encryptor.getKey();
			Iterator it = recipientInfoGenerators.iterator();

			while (it.hasNext())
			{
				RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

				recipientInfos.add(recipient.generate(encKey));
			}

			return open(dataType, @out, recipientInfos, encryptor);
		}

		public virtual OutputStream open(ASN1ObjectIdentifier dataType, OutputStream @out, ASN1EncodableVector recipientInfos, OutputEncryptor encryptor)
		{
			//
			// ContentInfo
			//
			BERSequenceGenerator cGen = new BERSequenceGenerator(@out);

			cGen.addObject(CMSObjectIdentifiers_Fields.envelopedData);

			//
			// Encrypted Data
			//
			BERSequenceGenerator envGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

			envGen.addObject(getVersion());

			if (originatorInfo != null)
			{
				envGen.addObject(new DERTaggedObject(false, 0, originatorInfo));
			}

			if (_berEncodeRecipientSet)
			{
				envGen.getRawOutputStream().write((new BERSet(recipientInfos)).getEncoded());
			}
			else
			{
				envGen.getRawOutputStream().write((new DERSet(recipientInfos)).getEncoded());
			}

			BERSequenceGenerator eiGen = new BERSequenceGenerator(envGen.getRawOutputStream());

			eiGen.addObject(dataType);

			AlgorithmIdentifier encAlgId = encryptor.getAlgorithmIdentifier();

			eiGen.getRawOutputStream().write(encAlgId.getEncoded());

			OutputStream octetStream = CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, false, _bufferSize);

			OutputStream cOut = encryptor.getOutputStream(octetStream);

			return new CmsEnvelopedDataOutputStream(this, cOut, cGen, envGen, eiGen);
		}

		public virtual OutputStream open(OutputStream @out, ASN1EncodableVector recipientInfos, OutputEncryptor encryptor)
		{
			try
			{
				//
				// ContentInfo
				//
				BERSequenceGenerator cGen = new BERSequenceGenerator(@out);

				cGen.addObject(CMSObjectIdentifiers_Fields.envelopedData);

				//
				// Encrypted Data
				//
				BERSequenceGenerator envGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

				ASN1Set recipients;
				if (_berEncodeRecipientSet)
				{
					recipients = new BERSet(recipientInfos);
				}
				else
				{
					recipients = new DERSet(recipientInfos);
				}

				envGen.addObject(new ASN1Integer(EnvelopedData.calculateVersion(originatorInfo, recipients, _unprotectedAttributes)));

				if (originatorInfo != null)
				{
					envGen.addObject(new DERTaggedObject(false, 0, originatorInfo));
				}

				envGen.getRawOutputStream().write(recipients.getEncoded());

				BERSequenceGenerator eiGen = new BERSequenceGenerator(envGen.getRawOutputStream());

				eiGen.addObject(CMSObjectIdentifiers_Fields.data);

				AlgorithmIdentifier encAlgId = encryptor.getAlgorithmIdentifier();

				eiGen.getRawOutputStream().write(encAlgId.getEncoded());

				OutputStream octetStream = CMSUtils.createBEROctetOutputStream(eiGen.getRawOutputStream(), 0, false, _bufferSize);

				return new CmsEnvelopedDataOutputStream(this, encryptor.getOutputStream(octetStream), cGen, envGen, eiGen);
			}
			catch (IOException e)
			{
				throw new CMSException("exception decoding algorithm parameters.", e);
			}
		}

		/// <summary>
		/// generate an enveloped object that contains an CMS Enveloped Data
		/// object using the given encryptor.
		/// </summary>
		public virtual OutputStream open(OutputStream @out, OutputEncryptor encryptor)
		{
			return doOpen(new ASN1ObjectIdentifier(CMSObjectIdentifiers_Fields.data.getId()), @out, encryptor);
		}

		/// <summary>
		/// generate an enveloped object that contains an CMS Enveloped Data
		/// object using the given encryptor and marking the data as being of the passed
		/// in type.
		/// </summary>
		public virtual OutputStream open(ASN1ObjectIdentifier dataType, OutputStream @out, OutputEncryptor encryptor)
		{
			return doOpen(dataType, @out, encryptor);
		}

		public class CmsEnvelopedDataOutputStream : OutputStream
		{
			private readonly CMSEnvelopedDataStreamGenerator outerInstance;

			internal OutputStream _out;
			internal BERSequenceGenerator _cGen;
			internal BERSequenceGenerator _envGen;
			internal BERSequenceGenerator _eiGen;

			public CmsEnvelopedDataOutputStream(CMSEnvelopedDataStreamGenerator outerInstance, OutputStream @out, BERSequenceGenerator cGen, BERSequenceGenerator envGen, BERSequenceGenerator eiGen)
			{
				this.outerInstance = outerInstance;
				_out = @out;
				_cGen = cGen;
				_envGen = envGen;
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

				if (outerInstance.unprotectedAttributeGenerator != null)
				{
					AttributeTable attrTable = outerInstance.unprotectedAttributeGenerator.getAttributes(new HashMap());

					ASN1Set unprotectedAttrs = new BERSet(attrTable.toASN1EncodableVector());

					_envGen.addObject(new DERTaggedObject(false, 1, unprotectedAttrs));
				}

				_envGen.close();
				_cGen.close();
			}
		}
	}

}