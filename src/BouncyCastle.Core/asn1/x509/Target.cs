using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// Target structure used in target information extension for attribute
	/// certificates from RFC 3281.
	/// 
	/// <pre>
	///     Target  ::= CHOICE {
	///       targetName          [0] GeneralName,
	///       targetGroup         [1] GeneralName,
	///       targetCert          [2] TargetCert
	///     }
	/// </pre>
	/// 
	/// <para>
	/// The targetCert field is currently not supported and must not be used
	/// according to RFC 3281.
	/// </para>
	/// </summary>
	public class Target : ASN1Object, ASN1Choice
	{
		public const int targetName = 0;
		public const int targetGroup = 1;

		private GeneralName targName;
		private GeneralName targGroup;

		/// <summary>
		/// Creates an instance of a Target from the given object.
		/// <para>
		/// <code>obj</code> can be a Target or a <seealso cref="ASN1TaggedObject"/>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> The object. </param>
		/// <returns> A Target instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the given object cannot be
		///             interpreted as Target. </exception>
		public static Target getInstance(object obj)
		{
			if (obj == null || obj is Target)
			{
				return (Target) obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new Target((ASN1TaggedObject)obj);
			}

			throw new IllegalArgumentException("unknown object in factory: " + obj.GetType());
		}

		/// <summary>
		/// Constructor from ASN1TaggedObject.
		/// </summary>
		/// <param name="tagObj"> The tagged object. </param>
		/// <exception cref="IllegalArgumentException"> if the encoding is wrong. </exception>
		private Target(ASN1TaggedObject tagObj)
		{
			switch (tagObj.getTagNo())
			{
			case targetName: // GeneralName is already a choice so explicit
				targName = GeneralName.getInstance(tagObj, true);
				break;
			case targetGroup:
				targGroup = GeneralName.getInstance(tagObj, true);
				break;
			default:
				throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
			}
		}

		/// <summary>
		/// Constructor from given details.
		/// <para>
		/// Exactly one of the parameters must be not <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="type"> the choice type to apply to the name. </param>
		/// <param name="name"> the general name. </param>
		/// <exception cref="IllegalArgumentException"> if type is invalid. </exception>
		public Target(int type, GeneralName name) : this(new DERTaggedObject(type, name))
		{
		}

		/// <returns> Returns the targetGroup. </returns>
		public virtual GeneralName getTargetGroup()
		{
			return targGroup;
		}

		/// <returns> Returns the targetName. </returns>
		public virtual GeneralName getTargetName()
		{
			return targName;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// 
		/// Returns:
		/// 
		/// <pre>
		///     Target  ::= CHOICE {
		///       targetName          [0] GeneralName,
		///       targetGroup         [1] GeneralName,
		///       targetCert          [2] TargetCert
		///     }
		/// </pre>
		/// </summary>
		/// <returns> a ASN1Primitive </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			// GeneralName is a choice already so most be explicitly tagged
			if (targName != null)
			{
				return new DERTaggedObject(true, 0, targName);
			}
			else
			{
				return new DERTaggedObject(true, 1, targGroup);
			}
		}
	}

}