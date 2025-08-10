using Razorpay.Api;

public class RazorpayService
{
    private readonly string _key;
    private readonly string _secret;

    public RazorpayService(IConfiguration config)
    {
        _key = config["Razorpay:Key"];
        _secret = config["Razorpay:Secret"];
        RazorpayClient client = new RazorpayClient(_key, _secret);
    }

    public Order CreateOrder(decimal amount, string currency = "INR")
    {
        RazorpayClient client = new RazorpayClient(_key, _secret);

        Dictionary<string, object> options = new Dictionary<string, object>
        {
            { "amount", amount * 87 }, // Razorpay takes amount in paise
            { "currency", currency },
            { "payment_capture", 1 }
        };

        Order order = client.Order.Create(options);
        return order;
    }
}
