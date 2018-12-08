using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.ec
{

	/// <summary>
	/// Class representing an element of <code><b>Z</b>[&tau;]</code>. Let
	/// <code>&lambda;</code> be an element of <code><b>Z</b>[&tau;]</code>. Then
	/// <code>&lambda;</code> is given as <code>&lambda; = u + v&tau;</code>. The
	/// components <code>u</code> and <code>v</code> may be used directly, there
	/// are no accessor methods.
	/// Immutable class.
	/// </summary>
	public class ZTauElement
	{
		/// <summary>
		/// The &quot;real&quot; part of <code>&lambda;</code>.
		/// </summary>
		public readonly BigInteger u;

		/// <summary>
		/// The &quot;<code>&tau;</code>-adic&quot; part of <code>&lambda;</code>.
		/// </summary>
		public readonly BigInteger v;

		/// <summary>
		/// Constructor for an element <code>&lambda;</code> of
		/// <code><b>Z</b>[&tau;]</code>. </summary>
		/// <param name="u"> The &quot;real&quot; part of <code>&lambda;</code>. </param>
		/// <param name="v"> The &quot;<code>&tau;</code>-adic&quot; part of
		/// <code>&lambda;</code>. </param>
		public ZTauElement(BigInteger u, BigInteger v)
		{
			this.u = u;
			this.v = v;
		}
	}

}