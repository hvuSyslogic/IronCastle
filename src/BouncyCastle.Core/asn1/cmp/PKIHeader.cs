using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmp
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class PKIHeader : ASN1Object
	{
		/// <summary>
		/// Value for a "null" recipient or sender.
		/// </summary>
		public static readonly GeneralName NULL_NAME = new GeneralName(X500Name.getInstance(new DERSequence()));

		public const int CMP_1999 = 1;
		public const int CMP_2000 = 2;

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

		private PKIHeader(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			pvno = ASN1Integer.getInstance(en.nextElement());
			sender = GeneralName.getInstance(en.nextElement());
			recipient = GeneralName.getInstance(en.nextElement());

			while (en.hasMoreElements())
			{
				ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

				switch (tObj.getTagNo())
				{
				case 0:
					messageTime = ASN1GeneralizedTime.getInstance(tObj, true);
					break;
				case 1:
					protectionAlg = AlgorithmIdentifier.getInstance(tObj, true);
					break;
				case 2:
					senderKID = ASN1OctetString.getInstance(tObj, true);
					break;
				case 3:
					recipKID = ASN1OctetString.getInstance(tObj, true);
					break;
				case 4:
					transactionID = ASN1OctetString.getInstance(tObj, true);
					break;
				case 5:
					senderNonce = ASN1OctetString.getInstance(tObj, true);
					break;
				case 6:
					recipNonce = ASN1OctetString.getInstance(tObj, true);
					break;
				case 7:
					freeText = PKIFreeText.getInstance(tObj, true);
					break;
				case 8:
					generalInfo = ASN1Sequence.getInstance(tObj, true);
					break;
				default:
					throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
				}
			}
		}

		public static PKIHeader getInstance(object o)
		{
			if (o is PKIHeader)
			{
				return (PKIHeader)o;
			}

			if (o != null)
			{
				return new PKIHeader(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public PKIHeader(int pvno, GeneralName sender, GeneralName recipient) : this(new ASN1Integer(pvno), sender, recipient)
		{
		}

		private PKIHeader(ASN1Integer pvno, GeneralName sender, GeneralName recipient)
		{
			this.pvno = pvno;
			this.sender = sender;
			this.recipient = recipient;
		}

		public virtual ASN1Integer getPvno()
		{
			return pvno;
		}

		public virtual GeneralName getSender()
		{
			return sender;
		}

		public virtual GeneralName getRecipient()
		{
			return recipient;
		}

		public virtual ASN1GeneralizedTime getMessageTime()
		{
			return messageTime;
		}

		public virtual AlgorithmIdentifier getProtectionAlg()
		{
			return protectionAlg;
		}

		public virtual ASN1OctetString getSenderKID()
		{
			return senderKID;
		}

		public virtual ASN1OctetString getRecipKID()
		{
			return recipKID;
		}

		public virtual ASN1OctetString getTransactionID()
		{
			return transactionID;
		}

		public virtual ASN1OctetString getSenderNonce()
		{
			return senderNonce;
		}

		public virtual ASN1OctetString getRecipNonce()
		{
			return recipNonce;
		}

		public virtual PKIFreeText getFreeText()
		{
			return freeText;
		}

		public virtual InfoTypeAndValue[] getGeneralInfo()
		{
			if (generalInfo == null)
			{
				return null;
			}
			InfoTypeAndValue[] results = new InfoTypeAndValue[generalInfo.size()];
			for (int i = 0; i < results.Length; i++)
			{
				results[i] = InfoTypeAndValue.getInstance(generalInfo.getObjectAt(i));
			}
			return results;
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
		/// </pre>
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
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

			return new DERSequence(v);
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