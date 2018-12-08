using System.IO;

namespace org.bouncycastle.util.io.pem
{

	/// <summary>
	/// Base interface for parsers to convert PEM objects into specific objects.
	/// </summary>
	public interface PemObjectParser
	{
		/// <summary>
		/// Parse an object out of the PEM object passed in.
		/// </summary>
		/// <param name="obj"> the PEM object containing the details for the specific object. </param>
		/// <returns> a specific object represented by the  PEM object. </returns>
		/// <exception cref="IOException"> on a parsing error. </exception>
		object parseObject(PemObject obj);
	}

}