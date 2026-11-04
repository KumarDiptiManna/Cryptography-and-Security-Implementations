module fulladder1(a, b, c, sum, carry);
    input a, b, c;
    output sum, carry;
    wire sum, carry;
    assign sum   = a ^ b ^ c;
    assign carry = (a & b) | (b & c) | (a & c);
endmodule

module main();
    reg  a, b, c;
    wire sum1, carry1;

    fulladder1 add1(a, b, c, sum1, carry1);

    initial
    begin
        $monitor("%b + %b + %b = %b, carry = %b", a, b, c, sum1, carry1);
                a = 0; b = 0; c = 0;
        #5    a = 0; b = 0; c = 1;
        #5    a = 0; b = 1; c = 0;
        #5    a = 0; b = 1; c = 1;
        #5    a = 1; b = 0; c = 0;
        #5    a = 1; b = 0; c = 1;
        #5    a = 1; b = 1; c = 0;
        #5    a = 1; b = 1; c = 1;
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)