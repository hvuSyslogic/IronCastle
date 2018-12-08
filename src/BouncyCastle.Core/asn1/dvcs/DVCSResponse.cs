using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.dvcs
{


	/// <summary>
	/// <pre>
	///     DVCSResponse ::= CHOICE
	///     {
	///         dvCertInfo         DVCSCertInfo ,
	///         dvErrorNote        [0] DVCSErrorNotice
	///     }
	/// </pre>
	/// </summary>

	public class DVCSResponse : ASN1Object, ASN1Choice
	{
		private DVCSCertInfo dvCertInfo;
		private DVCSErrorNotice dvErrorNote;

		public DVCSResponse(DVCSCertInfo dvCertInfo)
		{
			this.dvCertInfo = dvCertInfo;
		}

		public DVCSResponse(DVCSErrorNotice dvErrorNote)
		{
			this.dvErrorNote = dvErrorNote;
		}

		public static DVCSResponse getInstance(object obj)
		{
			if (obj == null || obj is DVCSResponse)
			{
				return (DVCSResponse)obj;
			}
			else
			{
				if (obj is byte[])
				{
					try
					{
						return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
					}
					catch (IOException e)
					{
						throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.Message);
					}
				}
				if (obj is ASN1Sequence)
				{
					DVCSCertInfo dvCertInfo = DVCSCertInfo.getInstance(obj);

					return new DVCSResponse(dvCertInfo);
				}
				if (obj is ASN1TaggedObject)
				{
					ASN1TaggedObject t = ASN1TaggedObject.getInstance(obj);
					DVCSErrorNotice dvErrorNote = DVCSErrorNotice.getInstance(t, false);

					return new DVCSResponse(dvErrorNote);
				}
			}

			throw new IllegalArgumentException("Couldn't convert from object to DVCSResponse: " + obj.GetType().getName());
		}

		public static DVCSResponse getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public virtual DVCSCertInfo getCertInfo()
		{
			return dvCertInfo;
		}

		public virtual DVCSErrorNotice getErrorNotice()
		{
			return dvErrorNote;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (dvCertInfo != null)
			{
				return dvCertInfo.toASN1Primitive();
			}
			else
			{
				return new DERTaggedObject(false, 0, dvErrorNote);
			}
		}

		public override string ToString()
		{
			if (dvCertInfo != null)
			{
				return "DVCSResponse {\ndvCertInfo: " + dvCertInfo.ToString() + "}\n";
			}
			else
			{
				return "DVCSResponse {\ndvErrorNote: " + dvErrorNote.ToString() + "}\n";
			}
		}
	}

}