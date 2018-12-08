using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// Target information extension for attributes certificates according to RFC
	/// 3281.
	/// 
	/// <pre>
	///           SEQUENCE OF Targets
	/// </pre>
	/// 
	/// </summary>
	public class TargetInformation : ASN1Object
	{
		private ASN1Sequence targets;

		/// <summary>
		/// Creates an instance of a TargetInformation from the given object.
		/// <para>
		/// <code>obj</code> can be a TargetInformation or a <seealso cref="ASN1Sequence"/>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> The object. </param>
		/// <returns> A TargetInformation instance. </returns>
		/// <exception cref="IllegalArgumentException"> if the given object cannot be
		///             interpreted as TargetInformation. </exception>
		public static TargetInformation getInstance(object obj)
		{
			if (obj is TargetInformation)
			{
				return (TargetInformation)obj;
			}
			else if (obj != null)
			{
				return new TargetInformation(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from a ASN1Sequence.
		/// </summary>
		/// <param name="seq"> The ASN1Sequence. </param>
		/// <exception cref="IllegalArgumentException"> if the sequence does not contain
		///             correctly encoded Targets elements. </exception>
		private TargetInformation(ASN1Sequence seq)
		{
			targets = seq;
		}

		/// <summary>
		/// Returns the targets in this target information extension.
		/// </summary>
		/// <returns> Returns the targets. </returns>
		public virtual Targets[] getTargetsObjects()
		{
			Targets[] copy = new Targets[targets.size()];
			int count = 0;
			for (Enumeration e = targets.getObjects(); e.hasMoreElements();)
			{
				copy[count++] = Targets.getInstance(e.nextElement());
			}
			return copy;
		}

		/// <summary>
		/// Constructs a target information from a single targets element. 
		/// According to RFC 3281 only one targets element must be produced.
		/// </summary>
		/// <param name="targets"> A Targets instance. </param>
		public TargetInformation(Targets targets)
		{
			this.targets = new DERSequence(targets);
		}

		/// <summary>
		/// According to RFC 3281 only one targets element must be produced. If
		/// multiple targets are given they must be merged in
		/// into one targets element.
		/// </summary>
		/// <param name="targets"> An array with <seealso cref="Targets"/>. </param>
		public TargetInformation(Target[] targets) : this(new Targets(targets))
		{
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// 
		/// Returns:
		/// 
		/// <pre>
		///          SEQUENCE OF Targets
		/// </pre>
		/// 
		/// <para>
		/// According to RFC 3281 only one targets element must be produced. If
		/// multiple targets are given in the constructor they are merged into one
		/// targets element. If this was produced from a
		/// <seealso cref="org.bouncycastle.asn1.ASN1Sequence"/> the encoding is kept.
		/// 
		/// </para>
		/// </summary>
		/// <returns> a ASN1Primitive </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return targets;
		}
	}

}