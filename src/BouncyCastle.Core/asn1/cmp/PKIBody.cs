using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{
	using CertReqMessages = org.bouncycastle.asn1.crmf.CertReqMessages;
	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;

	public class PKIBody : ASN1Object, ASN1Choice
	{
		public const int TYPE_INIT_REQ = 0;
		public const int TYPE_INIT_REP = 1;
		public const int TYPE_CERT_REQ = 2;
		public const int TYPE_CERT_REP = 3;
		public const int TYPE_P10_CERT_REQ = 4;
		public const int TYPE_POPO_CHALL = 5;
		public const int TYPE_POPO_REP = 6;
		public const int TYPE_KEY_UPDATE_REQ = 7;
		public const int TYPE_KEY_UPDATE_REP = 8;
		public const int TYPE_KEY_RECOVERY_REQ = 9;
		public const int TYPE_KEY_RECOVERY_REP = 10;
		public const int TYPE_REVOCATION_REQ = 11;
		public const int TYPE_REVOCATION_REP = 12;
		public const int TYPE_CROSS_CERT_REQ = 13;
		public const int TYPE_CROSS_CERT_REP = 14;
		public const int TYPE_CA_KEY_UPDATE_ANN = 15;
		public const int TYPE_CERT_ANN = 16;
		public const int TYPE_REVOCATION_ANN = 17;
		public const int TYPE_CRL_ANN = 18;
		public const int TYPE_CONFIRM = 19;
		public const int TYPE_NESTED = 20;
		public const int TYPE_GEN_MSG = 21;
		public const int TYPE_GEN_REP = 22;
		public const int TYPE_ERROR = 23;
		public const int TYPE_CERT_CONFIRM = 24;
		public const int TYPE_POLL_REQ = 25;
		public const int TYPE_POLL_REP = 26;

		private int tagNo;
		private ASN1Encodable body;

		public static PKIBody getInstance(object o)
		{
			if (o == null || o is PKIBody)
			{
				return (PKIBody)o;
			}

			if (o is ASN1TaggedObject)
			{
				return new PKIBody((ASN1TaggedObject)o);
			}

			throw new IllegalArgumentException("Invalid object: " + o.GetType().getName());
		}

		private PKIBody(ASN1TaggedObject tagged)
		{
			tagNo = tagged.getTagNo();
			body = getBodyForType(tagNo, tagged.getObject());
		}

		/// <summary>
		/// Creates a new PKIBody. </summary>
		/// <param name="type"> one of the TYPE_* constants </param>
		/// <param name="content"> message content </param>
		public PKIBody(int type, ASN1Encodable content)
		{
			tagNo = type;
			body = getBodyForType(type, content);
		}

		private static ASN1Encodable getBodyForType(int type, ASN1Encodable o)
		{
			switch (type)
			{
			case TYPE_INIT_REQ:
				return CertReqMessages.getInstance(o);
			case TYPE_INIT_REP:
				return CertRepMessage.getInstance(o);
			case TYPE_CERT_REQ:
				return CertReqMessages.getInstance(o);
			case TYPE_CERT_REP:
				return CertRepMessage.getInstance(o);
			case TYPE_P10_CERT_REQ:
				return CertificationRequest.getInstance(o);
			case TYPE_POPO_CHALL:
				return POPODecKeyChallContent.getInstance(o);
			case TYPE_POPO_REP:
				return POPODecKeyRespContent.getInstance(o);
			case TYPE_KEY_UPDATE_REQ:
				return CertReqMessages.getInstance(o);
			case TYPE_KEY_UPDATE_REP:
				return CertRepMessage.getInstance(o);
			case TYPE_KEY_RECOVERY_REQ:
				return CertReqMessages.getInstance(o);
			case TYPE_KEY_RECOVERY_REP:
				return KeyRecRepContent.getInstance(o);
			case TYPE_REVOCATION_REQ:
				return RevReqContent.getInstance(o);
			case TYPE_REVOCATION_REP:
				return RevRepContent.getInstance(o);
			case TYPE_CROSS_CERT_REQ:
				return CertReqMessages.getInstance(o);
			case TYPE_CROSS_CERT_REP:
				return CertRepMessage.getInstance(o);
			case TYPE_CA_KEY_UPDATE_ANN:
				return CAKeyUpdAnnContent.getInstance(o);
			case TYPE_CERT_ANN:
				return CMPCertificate.getInstance(o);
			case TYPE_REVOCATION_ANN:
				return RevAnnContent.getInstance(o);
			case TYPE_CRL_ANN:
				return CRLAnnContent.getInstance(o);
			case TYPE_CONFIRM:
				return PKIConfirmContent.getInstance(o);
			case TYPE_NESTED:
				return PKIMessages.getInstance(o);
			case TYPE_GEN_MSG:
				return GenMsgContent.getInstance(o);
			case TYPE_GEN_REP:
				return GenRepContent.getInstance(o);
			case TYPE_ERROR:
				return ErrorMsgContent.getInstance(o);
			case TYPE_CERT_CONFIRM:
				return CertConfirmContent.getInstance(o);
			case TYPE_POLL_REQ:
				return PollReqContent.getInstance(o);
			case TYPE_POLL_REP:
				return PollRepContent.getInstance(o);
			default:
				throw new IllegalArgumentException("unknown tag number: " + type);
			}
		}

		public virtual int getType()
		{
			return tagNo;
		}

		public virtual ASN1Encodable getContent()
		{
			return body;
		}

		/// <summary>
		/// <pre>
		/// PKIBody ::= CHOICE {       -- message-specific body elements
		///        ir       [0]  CertReqMessages,        --Initialization Request
		///        ip       [1]  CertRepMessage,         --Initialization Response
		///        cr       [2]  CertReqMessages,        --Certification Request
		///        cp       [3]  CertRepMessage,         --Certification Response
		///        p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
		///        popdecc  [5]  POPODecKeyChallContent, --pop Challenge
		///        popdecr  [6]  POPODecKeyRespContent,  --pop Response
		///        kur      [7]  CertReqMessages,        --Key Update Request
		///        kup      [8]  CertRepMessage,         --Key Update Response
		///        krr      [9]  CertReqMessages,        --Key Recovery Request
		///        krp      [10] KeyRecRepContent,       --Key Recovery Response
		///        rr       [11] RevReqContent,          --Revocation Request
		///        rp       [12] RevRepContent,          --Revocation Response
		///        ccr      [13] CertReqMessages,        --Cross-Cert. Request
		///        ccp      [14] CertRepMessage,         --Cross-Cert. Response
		///        ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
		///        cann     [16] CertAnnContent,         --Certificate Ann.
		///        rann     [17] RevAnnContent,          --Revocation Ann.
		///        crlann   [18] CRLAnnContent,          --CRL Announcement
		///        pkiconf  [19] PKIConfirmContent,      --Confirmation
		///        nested   [20] NestedMessageContent,   --Nested Message
		///        genm     [21] GenMsgContent,          --General Message
		///        genp     [22] GenRepContent,          --General Response
		///        error    [23] ErrorMsgContent,        --Error Message
		///        certConf [24] CertConfirmContent,     --Certificate confirm
		///        pollReq  [25] PollReqContent,         --Polling request
		///        pollRep  [26] PollRepContent          --Polling response
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERTaggedObject(true, tagNo, body);
		}
	}

}