using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.cmp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using CMPCertificate = org.bouncycastle.asn1.cmp.CMPCertificate;
	using InfoTypeAndValue = org.bouncycastle.asn1.cmp.InfoTypeAndValue;
	using PKIBody = org.bouncycastle.asn1.cmp.PKIBody;
	using PKIFreeText = org.bouncycastle.asn1.cmp.PKIFreeText;
	using PKIHeader = org.bouncycastle.asn1.cmp.PKIHeader;
	using PKIHeaderBuilder = org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
	using PKIMessage = org.bouncycastle.asn1.cmp.PKIMessage;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;

	/// <summary>
	/// Builder for creating a protected PKI message.
	/// </summary>
	public class ProtectedPKIMessageBuilder
	{
		private PKIHeaderBuilder hdrBuilder;
		private PKIBody body;
		private List generalInfos = new ArrayList();
		private List extraCerts = new ArrayList();

		/// <summary>
		/// Commence a message with the header version CMP_2000.
		/// </summary>
		/// <param name="sender"> message sender. </param>
		/// <param name="recipient"> intended recipient. </param>
		public ProtectedPKIMessageBuilder(GeneralName sender, GeneralName recipient) : this(PKIHeader.CMP_2000, sender, recipient)
		{
		}

		/// <summary>
		/// Commence a message with a specific header type.
		/// </summary>
		/// <param name="pvno">  the version CMP_1999 or CMP_2000. </param>
		/// <param name="sender"> message sender. </param>
		/// <param name="recipient"> intended recipient. </param>
		public ProtectedPKIMessageBuilder(int pvno, GeneralName sender, GeneralName recipient)
		{
			hdrBuilder = new PKIHeaderBuilder(pvno, sender, recipient);
		}

		/// <summary>
		/// Set the identifier for the transaction the new message will belong to.
		/// </summary>
		/// <param name="tid">  the transaction ID. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setTransactionID(byte[] tid)
		{
			hdrBuilder.setTransactionID(tid);

			return this;
		}

		/// <summary>
		/// Include a human-readable message in the new message.
		/// </summary>
		/// <param name="freeText"> the contents of the human readable message, </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setFreeText(PKIFreeText freeText)
		{
			hdrBuilder.setFreeText(freeText);

			return this;
		}

		/// <summary>
		/// Add a generalInfo data record to the header of the new message.
		/// </summary>
		/// <param name="genInfo"> the generalInfo data to be added. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder addGeneralInfo(InfoTypeAndValue genInfo)
		{
			generalInfos.add(genInfo);

			return this;
		}

		/// <summary>
		/// Set the creation time for the new message.
		/// </summary>
		/// <param name="time"> the message creation time. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setMessageTime(DateTime time)
		{
			hdrBuilder.setMessageTime(new ASN1GeneralizedTime(time));

			return this;
		}

		/// <summary>
		/// Set the recipient key identifier for the key to be used to verify the new message.
		/// </summary>
		/// <param name="kid"> a key identifier. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setRecipKID(byte[] kid)
		{
			hdrBuilder.setRecipKID(kid);

			return this;
		}

		/// <summary>
		/// Set the recipient nonce field on the new message.
		/// </summary>
		/// <param name="nonce"> a NONCE, typically copied from the sender nonce of the previous message. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setRecipNonce(byte[] nonce)
		{
			hdrBuilder.setRecipNonce(nonce);

			return this;
		}

		/// <summary>
		/// Set the sender key identifier for the key used to protect the new message.
		/// </summary>
		/// <param name="kid"> a key identifier. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setSenderKID(byte[] kid)
		{
			hdrBuilder.setSenderKID(kid);

			return this;
		}

		/// <summary>
		/// Set the sender nonce field on the new message.
		/// </summary>
		/// <param name="nonce"> a NONCE, typically 128 bits of random data. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setSenderNonce(byte[] nonce)
		{
			hdrBuilder.setSenderNonce(nonce);

			return this;
		}

		/// <summary>
		/// Set the body for the new message
		/// </summary>
		/// <param name="body"> the message body. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder setBody(PKIBody body)
		{
			this.body = body;

			return this;
		}

		/// <summary>
		/// Add an "extra certificate" to the message.
		/// </summary>
		/// <param name="extraCert"> the extra certificate to add. </param>
		/// <returns> the current builder instance. </returns>
		public virtual ProtectedPKIMessageBuilder addCMPCertificate(X509CertificateHolder extraCert)
		{
			extraCerts.add(extraCert);

			return this;
		}

		/// <summary>
		/// Build a protected PKI message which has MAC based integrity protection.
		/// </summary>
		/// <param name="macCalculator"> MAC calculator. </param>
		/// <returns> the resulting protected PKI message. </returns>
		/// <exception cref="CMPException"> if the protection MAC cannot be calculated. </exception>
		public virtual ProtectedPKIMessage build(MacCalculator macCalculator)
		{
			finaliseHeader(macCalculator.getAlgorithmIdentifier());

			PKIHeader header = hdrBuilder.build();

			try
			{
				DERBitString protection = new DERBitString(calculateMac(macCalculator, header, body));

				return finaliseMessage(header, protection);
			}
			catch (IOException e)
			{
				throw new CMPException("unable to encode MAC input: " + e.Message, e);
			}
		}

		/// <summary>
		/// Build a protected PKI message which has MAC based integrity protection.
		/// </summary>
		/// <param name="signer"> the ContentSigner to be used to calculate the signature. </param>
		/// <returns> the resulting protected PKI message. </returns>
		/// <exception cref="CMPException"> if the protection signature cannot be calculated. </exception>
		public virtual ProtectedPKIMessage build(ContentSigner signer)
		{
			finaliseHeader(signer.getAlgorithmIdentifier());

			PKIHeader header = hdrBuilder.build();

			try
			{
				DERBitString protection = new DERBitString(calculateSignature(signer, header, body));

				return finaliseMessage(header, protection);
			}
			catch (IOException e)
			{
				throw new CMPException("unable to encode signature input: " + e.Message, e);
			}
		}

		private void finaliseHeader(AlgorithmIdentifier algorithmIdentifier)
		{
			hdrBuilder.setProtectionAlg(algorithmIdentifier);

			if (!generalInfos.isEmpty())
			{
				InfoTypeAndValue[] genInfos = new InfoTypeAndValue[generalInfos.size()];

				hdrBuilder.setGeneralInfo((InfoTypeAndValue[])generalInfos.toArray(genInfos));
			}
		}

		private ProtectedPKIMessage finaliseMessage(PKIHeader header, DERBitString protection)
		{
			if (!extraCerts.isEmpty())
			{
				CMPCertificate[] cmpCerts = new CMPCertificate[extraCerts.size()];

				for (int i = 0; i != cmpCerts.Length; i++)
				{
					cmpCerts[i] = new CMPCertificate(((X509CertificateHolder)extraCerts.get(i)).toASN1Structure());
				}

				return new ProtectedPKIMessage(new PKIMessage(header, body, protection, cmpCerts));
			}
			else
			{
				return new ProtectedPKIMessage(new PKIMessage(header, body, protection));
			}
		}

		private byte[] calculateSignature(ContentSigner signer, PKIHeader header, PKIBody body)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(header);
			v.add(body);

			OutputStream sOut = signer.getOutputStream();

			sOut.write((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER));

			sOut.close();

			return signer.getSignature();
		}

		private byte[] calculateMac(MacCalculator macCalculator, PKIHeader header, PKIBody body)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(header);
			v.add(body);

			OutputStream sOut = macCalculator.getOutputStream();

			sOut.write((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER));

			sOut.close();

			return macCalculator.getMac();
		}
	}

}