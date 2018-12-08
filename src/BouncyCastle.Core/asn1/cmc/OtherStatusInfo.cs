using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{


	/// <summary>
	/// Other info implements the choice component of CMCStatusInfoV2.
	/// <para>
	/// OtherStatusInfo ::= CHOICE {
	/// failInfo              CMCFailInfo,
	/// pendInfo              PendInfo,
	/// extendedFailInfo      ExtendedFailInfo
	/// }
	/// </para>
	/// </summary>
	public class OtherStatusInfo : ASN1Object, ASN1Choice
	{
		private readonly CMCFailInfo failInfo;
		private readonly PendInfo pendInfo;
		private readonly ExtendedFailInfo extendedFailInfo;

		public static OtherStatusInfo getInstance(object obj)
		{
			if (obj is OtherStatusInfo)
			{
				return (OtherStatusInfo)obj;
			}

			if (obj is ASN1Encodable)
			{
				ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();

				if (asn1Value is ASN1Integer) // CMCFail info is an asn1 integer.
				{
					return new OtherStatusInfo(CMCFailInfo.getInstance(asn1Value));
				}
				else if (asn1Value is ASN1Sequence) // PendInfo is a sequence.
				{
					if (((ASN1Sequence)asn1Value).getObjectAt(0) is ASN1ObjectIdentifier)
					{
						return new OtherStatusInfo(ExtendedFailInfo.getInstance(asn1Value));
					}
					return new OtherStatusInfo(PendInfo.getInstance(asn1Value));
				}
			}
			else if (obj is byte[])
			{
				try
				{
					return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("parsing error: " + e.Message);
				}
			}
			throw new IllegalArgumentException("unknown object in getInstance(): " + obj.GetType().getName());
		}

		public OtherStatusInfo(CMCFailInfo failInfo) : this(failInfo, null, null)
		{
		}

		public OtherStatusInfo(PendInfo pendInfo) : this(null, pendInfo, null)
		{
		}

		public OtherStatusInfo(ExtendedFailInfo extendedFailInfo) : this(null, null, extendedFailInfo)
		{
		}

		private OtherStatusInfo(CMCFailInfo failInfo, PendInfo pendInfo, ExtendedFailInfo extendedFailInfo)
		{
			this.failInfo = failInfo;
			this.pendInfo = pendInfo;
			this.extendedFailInfo = extendedFailInfo;
		}

		public virtual bool isPendingInfo()
		{
			return pendInfo != null;
		}

		public virtual bool isFailInfo()
		{
			return failInfo != null;
		}


		public virtual bool isExtendedFailInfo()
		{
			return extendedFailInfo != null;
		}


		public override ASN1Primitive toASN1Primitive()
		{
			if (pendInfo != null)
			{
				return pendInfo.toASN1Primitive();
			}
			else if (failInfo != null)
			{
				return failInfo.toASN1Primitive();
			}
			return extendedFailInfo.toASN1Primitive();
		}
	}

}