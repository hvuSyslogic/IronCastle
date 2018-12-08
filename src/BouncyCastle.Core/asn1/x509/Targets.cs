using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// Targets structure used in target information extension for attribute
	/// certificates from RFC 3281.
	/// 
	/// <pre>
	///            Targets ::= SEQUENCE OF Target
	/// 
	///            Target  ::= CHOICE {
	///              targetName          [0] GeneralName,
	///              targetGroup         [1] GeneralName,
	///              targetCert          [2] TargetCert
	///            }
	/// 
	///            TargetCert  ::= SEQUENCE {
	///              targetCertificate    IssuerSerial,
	///              targetName           GeneralName OPTIONAL,
	///              certDigestInfo       ObjectDigestInfo OPTIONAL
	///            }
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.x509.Target </seealso>
	/// <seealso cref= org.bouncycastle.asn1.x509.TargetInformation </seealso>
	public class Targets : ASN1Object
	{
		private ASN1Sequence targets;

		/// <summary>
		/// Creates an instance of a Targets from the given object.
		/// <para>
		/// <code>obj</code> can be a Targets or a <seealso cref="ASN1Sequence"/>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> The object. </param>
		/// <returns> A Targets instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the given object cannot be
		///             interpreted as Target. </exception>
		public static Targets getInstance(object obj)
		{
			if (obj is Targets)
			{
				return (Targets)obj;
			}
			else if (obj != null)
			{
				return new Targets(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// </summary>
		/// <param name="targets"> The ASN.1 SEQUENCE. </param>
		/// <exception cref="IllegalArgumentException"> if the contents of the sequence are
		///             invalid. </exception>
		private Targets(ASN1Sequence targets)
		{
			this.targets = targets;
		}

		/// <summary>
		/// Constructor from given targets.
		/// <para>
		/// The vector is copied.
		/// 
		/// </para>
		/// </summary>
		/// <param name="targets"> A <code>Vector</code> of <seealso cref="Target"/>s. </param>
		/// <seealso cref= Target </seealso>
		/// <exception cref="IllegalArgumentException"> if the vector contains not only Targets. </exception>
		public Targets(Target[] targets)
		{
			this.targets = new DERSequence(targets);
		}

		/// <summary>
		/// Returns the targets in a <code>Vector</code>.
		/// <para>
		/// The vector is cloned before it is returned.
		/// 
		/// </para>
		/// </summary>
		/// <returns> Returns the targets. </returns>
		public virtual Target[] getTargets()
		{
			Target[] targs = new Target[targets.size()];
			int count = 0;
			for (Enumeration e = targets.getObjects(); e.hasMoreElements();)
			{
				targs[count++] = Target.getInstance(e.nextElement());
			}
			return targs;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// 
		/// Returns:
		/// 
		/// <pre>
		///            Targets ::= SEQUENCE OF Target
		/// </pre>
		/// </summary>
		/// <returns> a ASN1Primitive </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return targets;
		}
	}

}