using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Streams = org.bouncycastle.util.io.Streams;

	public abstract class RecipientInformation
	{
		protected internal RecipientId rid;
		protected internal AlgorithmIdentifier keyEncAlg;
		protected internal AlgorithmIdentifier messageAlgorithm;
		protected internal CMSSecureReadable secureReadable;

		private AuthAttributesProvider additionalData;

		private byte[] resultMac;
		private RecipientOperator @operator;

		public RecipientInformation(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
		{
			this.keyEncAlg = keyEncAlg;
			this.messageAlgorithm = messageAlgorithm;
			this.secureReadable = secureReadable;
			this.additionalData = additionalData;
		}

		public virtual RecipientId getRID()
		{
			return rid;
		}

		private byte[] encodeObj(ASN1Encodable obj)
		{
			if (obj != null)
			{
				return obj.toASN1Primitive().getEncoded();
			}

			return null;
		}

		/// <summary>
		/// Return the key encryption algorithm details for the key in this recipient.
		/// </summary>
		/// <returns> AlgorithmIdentifier representing the key encryption algorithm. </returns>
		public virtual AlgorithmIdentifier getKeyEncryptionAlgorithm()
		{
			return keyEncAlg;
		}

		/// <summary>
		/// return the object identifier for the key encryption algorithm.
		/// </summary>
		/// <returns> OID for key encryption algorithm. </returns>
		public virtual string getKeyEncryptionAlgOID()
		{
			return keyEncAlg.getAlgorithm().getId();
		}

		/// <summary>
		/// return the ASN.1 encoded key encryption algorithm parameters, or null if
		/// there aren't any.
		/// </summary>
		/// <returns> ASN.1 encoding of key encryption algorithm parameters. </returns>
		public virtual byte[] getKeyEncryptionAlgParams()
		{
			try
			{
				return encodeObj(keyEncAlg.getParameters());
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting encryption parameters " + e);
			}
		}

		/// <summary>
		/// Return the content digest calculated during the read of the content if one has been generated. This will
		/// only happen if we are dealing with authenticated data and authenticated attributes are present.
		/// </summary>
		/// <returns> byte array containing the digest. </returns>
		public virtual byte[] getContentDigest()
		{
			if (secureReadable is CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)
			{
				return ((CMSEnvelopedHelper.CMSDigestAuthenticatedSecureReadable)secureReadable).getDigest();
			}

			return null;
		}

		/// <summary>
		/// Return the MAC calculated for the recipient. Note: this call is only meaningful once all
		/// the content has been read.
		/// </summary>
		/// <returns>  byte array containing the mac. </returns>
		public virtual byte[] getMac()
		{
			if (resultMac == null)
			{
				if (@operator.isMacBased())
				{
					if (additionalData != null)
					{
						try
						{
							Streams.drain(@operator.getInputStream(new ByteArrayInputStream(additionalData.getAuthAttributes().getEncoded(ASN1Encoding_Fields.DER))));
						}
						catch (IOException e)
						{
							throw new IllegalStateException("unable to drain input: " + e.Message);
						}
					}
					resultMac = @operator.getMac();
				}
			}

			return resultMac;
		}

		/// <summary>
		/// Return the decrypted/encapsulated content in the EnvelopedData after recovering the content
		/// encryption/MAC key using the passed in Recipient.
		/// </summary>
		/// <param name="recipient"> recipient object to use to recover content encryption key </param>
		/// <returns>  the content inside the EnvelopedData this RecipientInformation is associated with. </returns>
		/// <exception cref="CMSException"> if the content-encryption/MAC key cannot be recovered. </exception>
		public virtual byte[] getContent(Recipient recipient)
		{
			try
			{
				return CMSUtils.streamToByteArray(getContentStream(recipient).getContentStream());
			}
			catch (IOException e)
			{
				throw new CMSException("unable to parse internal stream: " + e.Message, e);
			}
		}

		/// <summary>
		/// Return a CMSTypedStream representing the content in the EnvelopedData after recovering the content
		/// encryption/MAC key using the passed in Recipient.
		/// </summary>
		/// <param name="recipient"> recipient object to use to recover content encryption key </param>
		/// <returns>  the content inside the EnvelopedData this RecipientInformation is associated with. </returns>
		/// <exception cref="CMSException"> if the content-encryption/MAC key cannot be recovered. </exception>
		public virtual CMSTypedStream getContentStream(Recipient recipient)
		{
			@operator = getRecipientOperator(recipient);

			if (additionalData != null)
			{
				return new CMSTypedStream(secureReadable.getInputStream());
			}

			return new CMSTypedStream(@operator.getInputStream(secureReadable.getInputStream()));
		}

		public abstract RecipientOperator getRecipientOperator(Recipient recipient);
	}

}