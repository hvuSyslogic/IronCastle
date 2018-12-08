using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The Holder object.
	/// <para>
	/// For an v2 attribute certificate this is:
	/// 
	/// <pre>
	///            Holder ::= SEQUENCE {
	///                  baseCertificateID   [0] IssuerSerial OPTIONAL,
	///                           -- the issuer and serial number of
	///                           -- the holder's Public Key Certificate
	///                  entityName          [1] GeneralNames OPTIONAL,
	///                           -- the name of the claimant or role
	///                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
	///                           -- used to directly authenticate the holder,
	///                           -- for example, an executable
	///            }
	/// </pre>
	/// 
	/// </para>
	/// <para>
	/// For an v1 attribute certificate this is:
	/// 
	/// <pre>
	///         subject CHOICE {
	///          baseCertificateID [0] EXPLICIT IssuerSerial,
	///          -- associated with a Public Key Certificate
	///          subjectName [1] EXPLICIT GeneralNames },
	///          -- associated with a name
	/// </pre>
	/// </para>
	/// </summary>
	public class Holder : ASN1Object
	{
		public const int V1_CERTIFICATE_HOLDER = 0;
		public const int V2_CERTIFICATE_HOLDER = 1;

		internal IssuerSerial baseCertificateID;

		internal GeneralNames entityName;

		internal ObjectDigestInfo objectDigestInfo;

		private int version = V2_CERTIFICATE_HOLDER;

		public static Holder getInstance(object obj)
		{
			if (obj is Holder)
			{
				return (Holder)obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new Holder(ASN1TaggedObject.getInstance(obj));
			}
			else if (obj != null)
			{
				return new Holder(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor for a holder for an V1 attribute certificate.
		/// </summary>
		/// <param name="tagObj"> The ASN.1 tagged holder object. </param>
		private Holder(ASN1TaggedObject tagObj)
		{
			switch (tagObj.getTagNo())
			{
			case 0:
				baseCertificateID = IssuerSerial.getInstance(tagObj, true);
				break;
			case 1:
				entityName = GeneralNames.getInstance(tagObj, true);
				break;
			default:
				throw new IllegalArgumentException("unknown tag in Holder");
			}
			version = 0;
		}

		/// <summary>
		/// Constructor for a holder for an V2 attribute certificate.
		/// </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private Holder(ASN1Sequence seq)
		{
			if (seq.size() > 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

				switch (tObj.getTagNo())
				{
				case 0:
					baseCertificateID = IssuerSerial.getInstance(tObj, false);
					break;
				case 1:
					entityName = GeneralNames.getInstance(tObj, false);
					break;
				case 2:
					objectDigestInfo = ObjectDigestInfo.getInstance(tObj, false);
					break;
				default:
					throw new IllegalArgumentException("unknown tag in Holder");
				}
			}
			version = 1;
		}

		public Holder(IssuerSerial baseCertificateID) : this(baseCertificateID, V2_CERTIFICATE_HOLDER)
		{
		}

		/// <summary>
		/// Constructs a holder from a IssuerSerial for a V1 or V2 certificate.
		/// . </summary>
		/// <param name="baseCertificateID"> The IssuerSerial. </param>
		/// <param name="version"> The version of the attribute certificate.  </param>
		public Holder(IssuerSerial baseCertificateID, int version)
		{
			this.baseCertificateID = baseCertificateID;
			this.version = version;
		}

		/// <summary>
		/// Returns 1 for V2 attribute certificates or 0 for V1 attribute
		/// certificates. </summary>
		/// <returns> The version of the attribute certificate. </returns>
		public virtual int getVersion()
		{
			return version;
		}

		/// <summary>
		/// Constructs a holder with an entityName for V2 attribute certificates.
		/// </summary>
		/// <param name="entityName"> The entity or subject name. </param>
		public Holder(GeneralNames entityName) : this(entityName, V2_CERTIFICATE_HOLDER)
		{
		}

		/// <summary>
		/// Constructs a holder with an entityName for V2 attribute certificates or
		/// with a subjectName for V1 attribute certificates.
		/// </summary>
		/// <param name="entityName"> The entity or subject name. </param>
		/// <param name="version"> The version of the attribute certificate.  </param>
		public Holder(GeneralNames entityName, int version)
		{
			this.entityName = entityName;
			this.version = version;
		}

		/// <summary>
		/// Constructs a holder from an object digest info.
		/// </summary>
		/// <param name="objectDigestInfo"> The object digest info object. </param>
		public Holder(ObjectDigestInfo objectDigestInfo)
		{
			this.objectDigestInfo = objectDigestInfo;
		}

		public virtual IssuerSerial getBaseCertificateID()
		{
			return baseCertificateID;
		}

		/// <summary>
		/// Returns the entityName for an V2 attribute certificate or the subjectName
		/// for an V1 attribute certificate.
		/// </summary>
		/// <returns> The entityname or subjectname. </returns>
		public virtual GeneralNames getEntityName()
		{
			return entityName;
		}

		public virtual ObjectDigestInfo getObjectDigestInfo()
		{
			return objectDigestInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (version == 1)
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				if (baseCertificateID != null)
				{
					v.add(new DERTaggedObject(false, 0, baseCertificateID));
				}

				if (entityName != null)
				{
					v.add(new DERTaggedObject(false, 1, entityName));
				}

				if (objectDigestInfo != null)
				{
					v.add(new DERTaggedObject(false, 2, objectDigestInfo));
				}

				return new DERSequence(v);
			}
			else
			{
				if (entityName != null)
				{
					return new DERTaggedObject(true, 1, entityName);
				}
				else
				{
					return new DERTaggedObject(true, 0, baseCertificateID);
				}
			}
		}
	}

}