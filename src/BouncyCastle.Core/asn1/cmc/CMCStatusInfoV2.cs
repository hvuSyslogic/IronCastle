using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	/// <summary>
	/// <pre>
	/// --  Replaces CMC Status Info
	/// --
	/// 
	/// id-cmc-statusInfoV2 OBJECT IDENTIFIER ::= {id-cmc 25}
	/// 
	/// CMCStatusInfoV2 ::= SEQUENCE {
	///  cMCStatus             CMCStatus,
	///  bodyList              SEQUENCE SIZE (1..MAX) OF BodyPartReference,
	///  statusString          UTF8String OPTIONAL,
	///  otherStatusInfo             OtherStatusInfo OPTIONAL
	/// }
	/// 
	/// OtherStatusInfo ::= CHOICE {
	///  failInfo              CMCFailInfo,
	///  pendInfo              PendInfo,
	///  extendedFailInfo      ExtendedFailInfo
	/// }
	/// 
	/// PendInfo ::= SEQUENCE {
	/// pendToken           OCTET STRING,
	/// pendTime            GeneralizedTime
	/// }
	/// 
	/// ExtendedFailInfo ::= SEQUENCE {
	/// failInfoOID            OBJECT IDENTIFIER,
	/// failInfoValue          ANY DEFINED BY failInfoOID
	/// }
	/// </pre>
	/// </summary>
	public class CMCStatusInfoV2 : ASN1Object
	{
		private readonly CMCStatus cMCStatus;
		private readonly ASN1Sequence bodyList;
		private readonly DERUTF8String statusString;
		private readonly OtherStatusInfo otherStatusInfo;

		public CMCStatusInfoV2(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherStatusInfo otherStatusInfo)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = bodyList;
			this.statusString = statusString;
			this.otherStatusInfo = otherStatusInfo;
		}

		private CMCStatusInfoV2(ASN1Sequence seq)
		{
			if (seq.size() < 2 || seq.size() > 4)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
			this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));

			if (seq.size() > 2)
			{
				if (seq.size() == 4)
				{
					this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
					this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(3));
				}
				else if (seq.getObjectAt(2) is DERUTF8String)
				{
					this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
					this.otherStatusInfo = null;
				}
				else
				{
					this.statusString = null;
					this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(2));
				}
			}
			else
			{
				this.statusString = null;
				this.otherStatusInfo = null;
			}
		}


		public virtual CMCStatus getcMCStatus()
		{
			return cMCStatus;
		}

		public virtual BodyPartID[] getBodyList()
		{
			return Utils.toBodyPartIDArray(bodyList);
		}

		public virtual DERUTF8String getStatusString()
		{
			return statusString;
		}

		public virtual OtherStatusInfo getOtherStatusInfo()
		{
			return otherStatusInfo;
		}

		public virtual bool hasOtherInfo()
		{
			return otherStatusInfo != null;
		}

		public static CMCStatusInfoV2 getInstance(object o)
		{
			if (o is CMCStatusInfoV2)
			{
				return (CMCStatusInfoV2)o;
			}

			if (o != null)
			{
				return new CMCStatusInfoV2(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(cMCStatus);
			v.add(bodyList);

			if (statusString != null)
			{
				v.add(statusString);
			}

			if (otherStatusInfo != null)
			{
				v.add(otherStatusInfo);
			}

			return new DERSequence(v);
		}
	}

}