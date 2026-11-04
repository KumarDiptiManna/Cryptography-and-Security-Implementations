module mux1(datain_0, datain_1, sel, mux_out);
    input datain_0, datain_1, sel;
    output mux_out;
    wire mux_out;
    assign mux_out = sel ? datain_1 : datain_0;
endmodule

module main();
    reg  d0, d1, sel;
    wire out1;

    mux1 m1(d0, d1, sel, out1);

    initial
    begin
        $monitor("d0=%b d1=%b sel=%b -> mux_out = %b", d0, d1, sel, out1);
                d0 = 0; d1 = 0; sel = 0;
        #5    d0 = 0; d1 = 0; sel = 1;
        #5    d0 = 0; d1 = 1; sel = 0;
        #5    d0 = 0; d1 = 1; sel = 1;
        #5    d0 = 1; d1 = 0; sel = 0;
        #5    d0 = 1; d1 = 0; sel = 1;
        #5    d0 = 1; d1 = 1; sel = 0;
        #5    d0 = 1; d1 = 1; sel = 1;
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)
