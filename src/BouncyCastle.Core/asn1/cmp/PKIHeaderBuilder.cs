﻿namespace org.bouncycastle.asn1.cmp
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class PKIHeaderBuilder
	{
		private ASN1Integer pvno;
		private GeneralName sender;
		private GeneralName recipient;
		private ASN1GeneralizedTime messageTime;
		private AlgorithmIdentifier protectionAlg;
		private ASN1OctetString senderKID; // KeyIdentifier
		private ASN1OctetString recipKID; // KeyIdentifier
		private ASN1OctetString transactionID;
		private ASN1OctetString senderNonce;
		private ASN1OctetString recipNonce;
		private PKIFreeText freeText;
		private ASN1Sequence generalInfo;

		public PKIHeaderBuilder(int pvno, GeneralName sender, GeneralName recipient) : this(new ASN1Integer(pvno), sender, recipient)
		{
		}

		private PKIHeaderBuilder(ASN1Integer pvno, GeneralName sender, GeneralName recipient)
		{
			this.pvno = pvno;
			this.sender = sender;
			this.recipient = recipient;
		}

		public virtual PKIHeaderBuilder setMessageTime(ASN1GeneralizedTime time)
		{
			messageTime = time;

			return this;
		}

		public virtual PKIHeaderBuilder setProtectionAlg(AlgorithmIdentifier aid)
		{
			protectionAlg = aid;

			return this;
		}

		public virtual PKIHeaderBuilder setSenderKID(byte[] kid)
		{
			return setSenderKID(kid == null ? null : new DEROctetString(kid));
		}

		public virtual PKIHeaderBuilder setSenderKID(ASN1OctetString kid)
		{
			senderKID = kid;

			return this;
		}

		public virtual PKIHeaderBuilder setRecipKID(byte[] kid)
		{
			return setRecipKID(kid == null ? null : new DEROctetString(kid));
		}

		public virtual PKIHeaderBuilder setRecipKID(DEROctetString kid)
		{
			recipKID = kid;

			return this;
		}

		public virtual PKIHeaderBuilder setTransactionID(byte[] tid)
		{
			return setTransactionID(tid == null ? null : new DEROctetString(tid));
		}

		public virtual PKIHeaderBuilder setTransactionID(ASN1OctetString tid)
		{
			transactionID = tid;

			return this;
		}

		public virtual PKIHeaderBuilder setSenderNonce(byte[] nonce)
		{
			return setSenderNonce(nonce == null ? null : new DEROctetString(nonce));
		}

		public virtual PKIHeaderBuilder setSenderNonce(ASN1OctetString nonce)
		{
			senderNonce = nonce;

			return this;
		}

		public virtual PKIHeaderBuilder setRecipNonce(byte[] nonce)
		{
			return setRecipNonce(nonce == null ? null : new DEROctetString(nonce));
		}

		public virtual PKIHeaderBuilder setRecipNonce(ASN1OctetString nonce)
		{
			recipNonce = nonce;

			return this;
		}

		public virtual PKIHeaderBuilder setFreeText(PKIFreeText text)
		{
			freeText = text;

			return this;
		}

		public virtual PKIHeaderBuilder setGeneralInfo(InfoTypeAndValue genInfo)
		{
			return setGeneralInfo(makeGeneralInfoSeq(genInfo));
		}

		public virtual PKIHeaderBuilder setGeneralInfo(InfoTypeAndValue[] genInfos)
		{
			return setGeneralInfo(makeGeneralInfoSeq(genInfos));
		}

		public virtual PKIHeaderBuilder setGeneralInfo(ASN1Sequence seqOfInfoTypeAndValue)
		{
			generalInfo = seqOfInfoTypeAndValue;

			return this;
		}

		private static ASN1Sequence makeGeneralInfoSeq(InfoTypeAndValue generalInfo)
		{
			return new DERSequence(generalInfo);
		}

		private static ASN1Sequence makeGeneralInfoSeq(InfoTypeAndValue[] generalInfos)
		{
			ASN1Sequence genInfoSeq = null;
			if (generalInfos != null)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();
				for (int i = 0; i < generalInfos.Length; i++)
				{
					v.add(generalInfos[i]);
				}
				genInfoSeq = new DERSequence(v);
			}
			return genInfoSeq;
		}

		/// <summary>
		/// <pre>
		///  PKIHeader ::= SEQUENCE {
		///            pvno                INTEGER     { cmp1999(1), cmp2000(2) },
		///            sender              GeneralName,
		///            -- identifies the sender
		///            recipient           GeneralName,
		///            -- identifies the intended recipient
		///            messageTime     [0] GeneralizedTime         OPTIONAL,
		///            -- time of production of this message (used when sender
		///            -- believes that the transport will be "suitable"; i.e.,
		///            -- that the time will still be meaningful upon receipt)
		///            protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
		///            -- algorithm used for calculation of protection bits
		///            senderKID       [2] KeyIdentifier           OPTIONAL,
		///            recipKID        [3] KeyIdentifier           OPTIONAL,
		///            -- to identify specific keys used for protection
		///            transactionID   [4] OCTET STRING            OPTIONAL,
		///            -- identifies the transaction; i.e., this will be the same in
		///            -- corresponding request, response, certConf, and PKIConf
		///            -- messages
		///            senderNonce     [5] OCTET STRING            OPTIONAL,
		///            recipNonce      [6] OCTET STRING            OPTIONAL,
		///            -- nonces used to provide replay protection, senderNonce
		///            -- is inserted by the creator of this message; recipNonce
		///            -- is a nonce previously inserted in a related message by
		///            -- the intended recipient of this message
		///            freeText        [7] PKIFreeText             OPTIONAL,
		///            -- this may be used to indicate context-specific instructions
		///            -- (this field is intended for human consumption)
		///            generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
		///                                 InfoTypeAndValue     OPTIONAL
		///            -- this may be used to convey context-specific information
		///            -- (this field not primarily intended for human consumption)
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public virtual PKIHeader build()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pvno);
			v.add(sender);
			v.add(recipient);
			addOptional(v, 0, messageTime);
			addOptional(v, 1, protectionAlg);
			addOptional(v, 2, senderKID);
			addOptional(v, 3, recipKID);
			addOptional(v, 4, transactionID);
			addOptional(v, 5, senderNonce);
			addOptional(v, 6, recipNonce);
			addOptional(v, 7, freeText);
			addOptional(v, 8, generalInfo);

			messageTime = null;
			protectionAlg = null;
			senderKID = null;
			recipKID = null;
			transactionID = null;
			senderNonce = null;
			recipNonce = null;
			freeText = null;
			generalInfo = null;

			return PKIHeader.getInstance(new DERSequence(v));
		}

		private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(new DERTaggedObject(true, tagNo, obj));
			}
		}
	}

}