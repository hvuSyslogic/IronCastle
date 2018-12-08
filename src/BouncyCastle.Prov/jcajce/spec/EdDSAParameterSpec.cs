using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.spec
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

	/// <summary>
	/// ParameterSpec for EdDSA signature algorithms.
	/// </summary>
	public class EdDSAParameterSpec : AlgorithmParameterSpec
	{
		public const string Ed25519 = "Ed25519";
		public const string Ed448 = "Ed448";

		private readonly string curveName;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="curveName"> name of the curve to specify. </param>
		public EdDSAParameterSpec(string curveName)
		{
			if (curveName.Equals(Ed25519, StringComparison.OrdinalIgnoreCase))
			{
				this.curveName = Ed25519;
			}
			else if (curveName.Equals(Ed448, StringComparison.OrdinalIgnoreCase))
			{
				this.curveName = Ed448;
			}
			else if (curveName.Equals(EdECObjectIdentifiers_Fields.id_Ed25519.getId()))
			{
				this.curveName = Ed25519;
			}
			else if (curveName.Equals(EdECObjectIdentifiers_Fields.id_Ed448.getId()))
			{
				this.curveName = Ed448;
			}
			else
			{
				throw new IllegalArgumentException("unrecognized curve name: " + curveName);
			}

		}

		/// <summary>
		/// Return the curve name specified by this parameterSpec.
		/// </summary>
		/// <returns> the name of the curve this parameterSpec specifies. </returns>
		public virtual string getCurveName()
		{
			return curveName;
		}
	}

}