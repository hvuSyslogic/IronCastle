using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.agreement.jpake
{

	/// <summary>
	/// A pre-computed prime order group for use during a J-PAKE exchange.
	/// <para>
	/// Typically a Schnorr group is used.  In general, J-PAKE can use any prime order group
	/// that is suitable for public key cryptography, including elliptic curve cryptography.
	/// </para>
	/// <para>
	/// See <seealso cref="JPAKEPrimeOrderGroups"/> for convenient standard groups.
	/// </para>
	/// <para>
	/// NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf">publishes</a>
	/// many groups that can be used for the desired level of security.
	/// </para>
	/// </summary>
	public class JPAKEPrimeOrderGroup
	{
		private readonly BigInteger p;
		private readonly BigInteger q;
		private readonly BigInteger g;

		/// <summary>
		/// Constructs a new <seealso cref="JPAKEPrimeOrderGroup"/>.
		/// <para>
		/// In general, you should use one of the pre-approved groups from
		/// <seealso cref="JPAKEPrimeOrderGroups"/>, rather than manually constructing one.
		/// </para>
		/// <para>
		/// The following basic checks are performed:
		/// <ul>
		/// <li>p-1 must be evenly divisible by q</li>
		/// <li>g must be in [2, p-1]</li>
		/// <li>g^q mod p must equal 1</li>
		/// <li>p must be prime (within reasonably certainty)</li>
		/// <li>q must be prime (within reasonably certainty)</li>
		/// </ul>
		/// </para>
		/// <para>
		/// The prime checks are performed using <seealso cref="BigInteger#isProbablePrime(int)"/>,
		/// and are therefore subject to the same probability guarantees.
		/// </para>
		/// <para>
		/// These checks prevent trivial mistakes.
		/// However, due to the small uncertainties if p and q are not prime,
		/// advanced attacks are not prevented.
		/// Use it at your own risk.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="NullPointerException"> if any argument is null </exception>
		/// <exception cref="IllegalArgumentException"> if any of the above validations fail </exception>
		public JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g) : this(p, q, g, false)
		{
			/*
			 * Don't skip the checks on user-specified groups.
			 */
		}

		/// <summary>
		/// Internal package-private constructor used by the pre-approved
		/// groups in <seealso cref="JPAKEPrimeOrderGroups"/>.
		/// These pre-approved groups can avoid the expensive checks.
		/// </summary>
		public JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g, bool skipChecks)
		{
			JPAKEUtil.validateNotNull(p, "p");
			JPAKEUtil.validateNotNull(q, "q");
			JPAKEUtil.validateNotNull(g, "g");

			if (!skipChecks)
			{
				if (!p.subtract(JPAKEUtil.ONE).mod(q).Equals(JPAKEUtil.ZERO))
				{
					throw new IllegalArgumentException("p-1 must be evenly divisible by q");
				}
				if (g.compareTo(BigInteger.valueOf(2)) == -1 || g.compareTo(p.subtract(JPAKEUtil.ONE)) == 1)
				{
					throw new IllegalArgumentException("g must be in [2, p-1]");
				}
				if (!g.modPow(q, p).Equals(JPAKEUtil.ONE))
				{
					throw new IllegalArgumentException("g^q mod p must equal 1");
				}
				/*
				 * Note that these checks do not guarantee that p and q are prime.
				 * We just have reasonable certainty that they are prime.
				 */
				if (!p.isProbablePrime(20))
				{
					throw new IllegalArgumentException("p must be prime");
				}
				if (!q.isProbablePrime(20))
				{
					throw new IllegalArgumentException("q must be prime");
				}
			}

			this.p = p;
			this.q = q;
			this.g = g;
		}

		public virtual BigInteger getP()
		{
			return p;
		}

		public virtual BigInteger getQ()
		{
			return q;
		}

		public virtual BigInteger getG()
		{
			return g;
		}

	}

}