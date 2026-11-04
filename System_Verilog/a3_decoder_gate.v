// 2-to-4 decoder with enable, gate primitives only
module decoder_gate(en, a, b, y);
    input en, a, b;
    output [3:0] y;
    wire na, nb;
    not (na, a);
    not (nb, b);
    and (y[0], en, na, nb);
    and (y[1], en, na, b );
    and (y[2], en, a,  nb);
    and (y[3], en, a,  b );
endmodule

module main();
    reg en, a, b;
    wire [3:0] y;
    integer i;

    decoder_gate d1(en, a, b, y);

    initial
    begin
        $monitor("en=%b a=%b b=%b -> y=%b", en, a, b, y);
        for (i = 0; i < 8; i = i + 1)
        begin
            {en, a, b} = i;
            #5;
        end
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)
