using System;

namespace org.bouncycastle.jcajce.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;

	/// <summary>
	/// General JCA/JCE utility methods.
	/// </summary>
	public class AlgorithmParametersUtils
	{


		private AlgorithmParametersUtils()
		{

		}

		/// <summary>
		/// Extract an ASN.1 encodable from an AlgorithmParameters object.
		/// </summary>
		/// <param name="params"> the object to get the encoding used to create the return value. </param>
		/// <returns> an ASN.1 object representing the primitives making up the params parameter. </returns>
		/// <exception cref="IOException"> if an encoding cannot be extracted. </exception>
		public static ASN1Encodable extractParameters(AlgorithmParameters @params)
		{
			// we try ASN.1 explicitly first just in case and then role back to the default.
			ASN1Encodable asn1Params;
			try
			{
				asn1Params = ASN1Primitive.fromByteArray(@params.getEncoded("ASN.1"));
			}
			catch (Exception)
			{
				asn1Params = ASN1Primitive.fromByteArray(@params.getEncoded());
			}

			return asn1Params;
		}

		/// <summary>
		/// Load an AlgorithmParameters object with the passed in ASN.1 encodable - if possible.
		/// </summary>
		/// <param name="params"> the AlgorithmParameters object to be initialised. </param>
		/// <param name="sParams"> the ASN.1 encodable to initialise params with. </param>
		/// <exception cref="IOException"> if the parameters cannot be initialised. </exception>
		public static void loadParameters(AlgorithmParameters @params, ASN1Encodable sParams)
		{
			// we try ASN.1 explicitly first just in case and then role back to the default.
			try
			{
				@params.init(sParams.toASN1Primitive().getEncoded(), "ASN.1");
			}
			catch (Exception)
			{
				@params.init(sParams.toASN1Primitive().getEncoded());
			}
		}
	}

}