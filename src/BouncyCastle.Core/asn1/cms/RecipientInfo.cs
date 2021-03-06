﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// RecipientInfo ::= CHOICE {
	///     ktri      KeyTransRecipientInfo,
	///     kari  [1] KeyAgreeRecipientInfo,
	///     kekri [2] KEKRecipientInfo,
	///     pwri  [3] PasswordRecipientInfo,
	///     ori   [4] OtherRecipientInfo }
	/// </pre>
	/// </para>
	/// </summary>
	public class RecipientInfo : ASN1Object, ASN1Choice
	{
		internal ASN1Encodable info;

		public RecipientInfo(KeyTransRecipientInfo info)
		{
			this.info = info;
		}

		public RecipientInfo(KeyAgreeRecipientInfo info)
		{
			this.info = new DERTaggedObject(false, 1, info);
		}

		public RecipientInfo(KEKRecipientInfo info)
		{
			this.info = new DERTaggedObject(false, 2, info);
		}

		public RecipientInfo(PasswordRecipientInfo info)
		{
			this.info = new DERTaggedObject(false, 3, info);
		}

		public RecipientInfo(OtherRecipientInfo info)
		{
			this.info = new DERTaggedObject(false, 4, info);
		}

		public RecipientInfo(ASN1Primitive info)
		{
			this.info = info;
		}

		/// <summary>
		/// Return a RecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="RecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with RecipientInfo structure inside
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject"/> input formats with RecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static RecipientInfo getInstance(object o)
		{
			if (o == null || o is RecipientInfo)
			{
				return (RecipientInfo)o;
			}
			else if (o is ASN1Sequence)
			{
				return new RecipientInfo((ASN1Sequence)o);
			}
			else if (o is ASN1TaggedObject)
			{
				return new RecipientInfo((ASN1TaggedObject)o);
			}

			throw new IllegalArgumentException("unknown object in factory: " + o.GetType().getName());
		}

		public virtual ASN1Integer getVersion()
		{
			if (info is ASN1TaggedObject)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)info;

				switch (o.getTagNo())
				{
				case 1:
					return KeyAgreeRecipientInfo.getInstance(o, false).getVersion();
				case 2:
					return getKEKInfo(o).getVersion();
				case 3:
					return PasswordRecipientInfo.getInstance(o, false).getVersion();
				case 4:
					return new ASN1Integer(0); // no syntax version for OtherRecipientInfo
				default:
					throw new IllegalStateException("unknown tag");
				}
			}

			return KeyTransRecipientInfo.getInstance(info).getVersion();
		}

		public virtual bool isTagged()
		{
			return (info is ASN1TaggedObject);
		}

		public virtual ASN1Encodable getInfo()
		{
			if (info is ASN1TaggedObject)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)info;

				switch (o.getTagNo())
				{
				case 1:
					return KeyAgreeRecipientInfo.getInstance(o, false);
				case 2:
					return getKEKInfo(o);
				case 3:
					return PasswordRecipientInfo.getInstance(o, false);
				case 4:
					return OtherRecipientInfo.getInstance(o, false);
				default:
					throw new IllegalStateException("unknown tag");
				}
			}

			return KeyTransRecipientInfo.getInstance(info);
		}

		private KEKRecipientInfo getKEKInfo(ASN1TaggedObject o)
		{
			if (o.isExplicit())
			{ // compatibilty with erroneous version
				return KEKRecipientInfo.getInstance(o, true);
			}
			else
			{
				return KEKRecipientInfo.getInstance(o, false);
			}
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return info.toASN1Primitive();
		}
	}

}